using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.Http;
using PkiProxy.Protocol;
using PkiProxy.Protocol.Wstep;

internal static class InboundSoapLimitsTests
{
    private const string Soap = "http://www.w3.org/2003/05/soap-envelope";

    internal static async Task RunAsync()
    {
        var checks = 0;
        void Check(bool value, string message) { if (!value) throw new InvalidOperationException(message); checks++; }
        var limits = InboundRequestLimits.Default;
        var basic = Bytes(Envelope("<t:op xmlns:t=\"urn:test\">ok</t:op>"));

        Check((await Read(basic, limits, basic.Length)).IsValid, "declared UTF-8 SOAP accepted");
        Check((await Read(basic, limits, null)).IsValid, "chunked-style SOAP accepted with the same bounds");
        Check(!(await Read(basic, limits, basic.Length - 1)).IsValid, "short declared length rejected");
        Check(!(await Read(basic, limits, basic.Length + 1)).IsValid, "long declared length rejected");

        var exactBody = Bytes(Envelope("<t:op xmlns:t=\"urn:test\"/>") +
            new string(' ', limits.MaximumBodyBytes - Bytes(Envelope("<t:op xmlns:t=\"urn:test\"/>")).Length));
        var bodyBoundaryLimits = limits with { MaximumTextCharacters = limits.MaximumBodyBytes + 1024 };
        Check(exactBody.Length == limits.MaximumBodyBytes &&
            (await Read(exactBody, bodyBoundaryLimits, exactBody.Length)).IsValid,
            "maximum body boundary accepted");
        var overBody = exactBody.Concat([(byte)' ']).ToArray();
        Check((await Read(overBody, bodyBoundaryLimits, null)).ErrorCode == "EnvelopeTooLarge", "maximum body plus one rejected");

        var depthLimits = limits with { MaximumXmlDepth = 5 };
        Check((await Read(Bytes(Envelope("<o><a><b><c/></b></a></o>")), depthLimits, null)).IsValid,
            "depth boundary accepted");
        Check((await Read(Bytes(Envelope("<o><a><b><c><d/></c></b></a></o>")), depthLimits, null)).ErrorCode ==
            "XmlDepthLimitExceeded", "depth boundary plus one rejected");

        var elementXml = Bytes(Envelope("<o><a/><b/><c/></o>"));
        Check((await Read(elementXml, limits with { MaximumXmlElements = 6 }, null)).IsValid,
            "element boundary accepted");
        Check((await Read(elementXml, limits with { MaximumXmlElements = 5 }, null)).ErrorCode ==
            "XmlElementLimitExceeded", "element boundary plus one rejected");

        var attributeXml = Bytes(Envelope("<o a=\"1\" b=\"2\" c=\"3\"/>"));
        Check((await Read(attributeXml, limits with { MaximumXmlAttributes = 4 }, null)).IsValid,
            "attribute boundary accepted");
        Check((await Read(attributeXml, limits with { MaximumXmlAttributes = 3 }, null)).ErrorCode ==
            "XmlAttributeLimitExceeded", "attribute boundary plus one rejected");

        var textLimits = limits with { MaximumTextNodeCharacters = 12 };
        Check((await Read(Bytes(Envelope("<o>123456789012</o>")), textLimits, null)).IsValid,
            "text token boundary accepted");
        Check((await Read(Bytes(Envelope("<o>1234567890123</o>")), textLimits, null)).ErrorCode ==
            "XmlTextNodeLimitExceeded", "text token boundary plus one rejected");

        var nodeXml = Bytes(Envelope("<o><a>1</a><b>2</b></o>"));
        var firstAcceptedNodeLimit = 0;
        for (var candidate = 1; candidate <= 64; candidate++)
            if ((await Read(nodeXml, limits with { MaximumXmlNodes = candidate }, null)).IsValid)
            { firstAcceptedNodeLimit = candidate; break; }
        Check(firstAcceptedNodeLimit > 1 &&
            !(await Read(nodeXml, limits with { MaximumXmlNodes = firstAcceptedNodeLimit - 1 }, null)).IsValid,
            "node boundary and one-over rejection are exact");

        foreach (var hostile in new[]
        {
            "<!DOCTYPE e [<!ENTITY x \"expanded\">]>" + Envelope("<o>&x;</o>"),
            "<!DOCTYPE e SYSTEM \"file:///not-read\">" + Envelope("<o/>")
        })
            Check(!(await Read(Bytes(hostile), limits, null)).IsValid, "DTD/entity input rejected");

        var malformedUtf8 = basic.ToArray();
        malformedUtf8[Array.IndexOf(malformedUtf8, (byte)'o')] = 0xff;
        Check((await Read(malformedUtf8, limits, null)).ErrorCode == "MalformedEncoding", "malformed UTF-8 rejected");
        Check(!(await Read(basic, limits, null, "text/xml")).IsValid, "content-type confusion rejected");
        Check(!(await Read(basic, limits, null, "application/soap+xml; charset=utf-16")).IsValid,
            "unadmitted charset rejected");
        Check(!(await Read(basic, limits, null, contentEncoding: "gzip")).IsValid,
            "compressed body rejected before parsing");

        var wst = (XNamespace)"http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        var wsse = (XNamespace)"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        var issue = new XElement(wst + "RequestSecurityToken",
            new XElement(wst + "TokenType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"),
            new XElement(wst + "RequestType", "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"),
            new XElement(wsse + "BinarySecurityToken",
                new XAttribute("EncodingType", wsse.NamespaceName + "#base64binary"), "AQID"));
        Check(WstepRequestContract.TryParse(issue, WstepRequestContract.EnrollmentAction, 3, out _, out _),
            "decoded binary boundary accepted");
        Check(!WstepRequestContract.TryParse(issue, WstepRequestContract.EnrollmentAction, 2, out _, out _),
            "decoded binary one-over rejected before decode");

        var timedOut = await ReadWithStream(new DelayedStream(), limits with { BodyReadTimeout = TimeSpan.FromMilliseconds(10) });
        Check(timedOut.ErrorCode == "RequestBodyTimeout", "slow body deadline rejected");
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        try
        {
            _ = await ReadWithStream(new DelayedStream(), limits, cancelled.Token);
            throw new InvalidOperationException("caller cancellation must propagate");
        }
        catch (OperationCanceledException) { checks++; }

        var downstreamCalls = 0;
        var attacks = await Task.WhenAll(Enumerable.Range(0, 48).Select(async _ =>
        {
            var parsed = await Read(overBody, limits, null);
            if (parsed.IsValid) Interlocked.Increment(ref downstreamCalls);
            return parsed;
        }));
        Check(attacks.All(result => !result.IsValid) && downstreamCalls == 0,
            "concurrent oversized requests stop before downstream signer, CA or store work");
        Console.WriteLine($"Central inbound SOAP/XML limit checks passed: {checks}.");
    }

    private static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);
    private static string Envelope(string operation) =>
        $"<s:Envelope xmlns:s=\"{Soap}\"><s:Body>{operation}</s:Body></s:Envelope>";

    private static Task<SoapReadResult> Read(byte[] body, InboundRequestLimits limits, long? contentLength,
        string contentType = "application/soap+xml; charset=utf-8", string? contentEncoding = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Body = new MemoryStream(body, writable: false);
        context.Request.ContentLength = contentLength;
        context.Request.ContentType = contentType;
        if (contentEncoding is not null) context.Request.Headers.ContentEncoding = contentEncoding;
        return SoapEnvelopeReader.ReadAsync(context.Request, limits, default);
    }

    private static Task<SoapReadResult> ReadWithStream(Stream stream, InboundRequestLimits limits,
        CancellationToken cancellationToken = default)
    {
        var context = new DefaultHttpContext();
        context.Request.Body = stream;
        context.Request.ContentType = "application/soap+xml; charset=utf-8";
        return SoapEnvelopeReader.ReadAsync(context.Request, limits, cancellationToken);
    }

    private sealed class DelayedStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0; }
    }
}
