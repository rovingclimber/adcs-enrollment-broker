using System.Xml;
using System.Xml.Linq;
using System.Buffers;
using System.Text;
using Microsoft.Net.Http.Headers;

namespace PkiProxy.Protocol;

internal static class SoapEnvelopeReader
{
    private static readonly XNamespace Soap12 = "http://www.w3.org/2003/05/soap-envelope";
    private static readonly XNamespace WsAddressing = "http://www.w3.org/2005/08/addressing";

    public static async Task<SoapReadResult> ReadAsync(
        HttpRequest request,
        InboundRequestLimits limits,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(limits);
        if (!ValidContentType(request) || request.Headers.ContentEncoding.Count != 0)
            return SoapReadResult.Invalid("UnsupportedSoapContentType");
        if (request.ContentLength is < 0 or > int.MaxValue || request.ContentLength > limits.MaximumBodyBytes)
            return SoapReadResult.Invalid("EnvelopeTooLarge");

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = limits.MaximumTextCharacters,
            MaxCharactersFromEntities = 0,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true
        };

        var rented = ArrayPool<byte>.Shared.Rent(limits.MaximumBodyBytes + 1);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(limits.BodyReadTimeout);
            var count = 0;
            while (count <= limits.MaximumBodyBytes)
            {
                var read = await request.Body.ReadAsync(rented.AsMemory(count,
                    limits.MaximumBodyBytes + 1 - count), deadline.Token);
                if (read == 0) break;
                count += read;
            }
            if (count == 0 || count > limits.MaximumBodyBytes ||
                request.ContentLength is { } declared && declared != count)
                return SoapReadResult.Invalid(count > limits.MaximumBodyBytes ? "EnvelopeTooLarge" : "InvalidContentLength");
            _ = new UTF8Encoding(false, true).GetCharCount(rented, 0, count);

            using (var structuralStream = new MemoryStream(rented, 0, count, writable: false))
            using (var structuralReader = XmlReader.Create(structuralStream, settings))
                ValidateStructure(structuralReader, limits);

            using var documentStream = new MemoryStream(rented, 0, count, writable: false);
            using var documentReader = XmlReader.Create(documentStream, settings);
            var document = XDocument.Load(documentReader, LoadOptions.None);

            return Parse(document, limits.MaximumDecodedBinaryBytes);
        }
        catch (InvalidOperationException)
        {
            return SoapReadResult.Invalid("MultipleSoapBodyOperations");
        }
        catch (XmlException)
        {
            return SoapReadResult.Invalid("MalformedXml");
        }
        catch (DecoderFallbackException)
        {
            return SoapReadResult.Invalid("MalformedEncoding");
        }
        catch (InboundLimitException exception)
        {
            return SoapReadResult.Invalid(exception.Code);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return SoapReadResult.Invalid("RequestBodyTimeout");
        }
        finally
        {
            Array.Clear(rented, 0, rented.Length);
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    internal static Task<SoapReadResult> ReadAsync(HttpRequest request, CancellationToken cancellationToken) =>
        ReadAsync(request, InboundRequestLimits.Default, cancellationToken);

    internal static SoapReadResult Parse(XDocument document, int maximumDecodedBinaryBytes =
        InboundRequestLimits.DefaultMaximumDecodedBinaryBytes)
    {
        if (document.Root?.Name != Soap12 + "Envelope")
        {
            return SoapReadResult.Invalid("UnsupportedSoapVersion");
        }

        try
        {
            // Do not select SOAP children by name while silently ignoring other
            // top-level elements.  That would make the security-relevant SOAP
            // envelope ambiguous to another intermediary with a different XML
            // interpretation.
            var envelopeChildren = document.Root.Elements().ToList();
            if (envelopeChildren.Count is < 1 or > 2 ||
                (envelopeChildren.Count == 2 && envelopeChildren[0].Name != Soap12 + "Header") ||
                envelopeChildren[^1].Name != Soap12 + "Body")
            {
                return SoapReadResult.Invalid("InvalidSoapEnvelopeStructure");
            }

            var header = envelopeChildren.Count == 2 ? envelopeChildren[0] : null;
            var action = SingleHeaderValue(header, WsAddressing + "Action", "DuplicateWsAddressingAction");
            var messageId = SingleHeaderValue(header, WsAddressing + "MessageID", "DuplicateWsAddressingMessageId");
            var body = envelopeChildren[^1];
            var operation = body?.Elements().SingleOrDefault();
            if (operation is null)
            {
                return SoapReadResult.Invalid("MissingSoapBodyOperation");
            }

            return SoapReadResult.Valid(operation, action, messageId, maximumDecodedBinaryBytes);
        }
        catch (InvalidOperationException exception) when (exception.Message.StartsWith("DuplicateWsAddressing", StringComparison.Ordinal))
        {
            return SoapReadResult.Invalid(exception.Message);
        }
        catch (InvalidOperationException)
        {
            return SoapReadResult.Invalid("InvalidSoapEnvelopeStructure");
        }
    }

    private static string? SingleHeaderValue(XElement? header, XName name, string duplicateErrorCode)
    {
        var values = header?.Elements(name).ToList() ?? [];
        if (values.Count > 1)
        {
            throw new InvalidOperationException(duplicateErrorCode);
        }

        return values.Count == 0 ? null : values[0].Value.Trim();
    }

    private static bool ValidContentType(HttpRequest request)
    {
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType) ||
            !string.Equals(contentType.MediaType.Value, "application/soap+xml", StringComparison.OrdinalIgnoreCase))
            return false;
        foreach (var parameter in contentType.Parameters)
            if (!string.Equals(parameter.Name.Value, "charset", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(parameter.Name.Value, "action", StringComparison.OrdinalIgnoreCase))
                return false;
        var charset = contentType.Charset.Value?.Trim('"');
        return string.IsNullOrEmpty(charset) || string.Equals(charset, "utf-8", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(charset, "utf8", StringComparison.OrdinalIgnoreCase);
    }

    private static void ValidateStructure(XmlReader reader, InboundRequestLimits limits)
    {
        var nodes = 0;
        var elements = 0;
        var attributes = 0;
        var text = 0L;
        while (reader.Read())
        {
            if (++nodes > limits.MaximumXmlNodes) throw new InboundLimitException("XmlNodeLimitExceeded");
            if (reader.Depth > limits.MaximumXmlDepth) throw new InboundLimitException("XmlDepthLimitExceeded");
            if (reader.NodeType == XmlNodeType.Element)
            {
                if (++elements > limits.MaximumXmlElements) throw new InboundLimitException("XmlElementLimitExceeded");
                attributes += reader.AttributeCount;
                if (attributes > limits.MaximumXmlAttributes) throw new InboundLimitException("XmlAttributeLimitExceeded");
            }
            if (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.SignificantWhitespace)
            {
                var length = reader.Value.Length;
                if (length > limits.MaximumTextNodeCharacters) throw new InboundLimitException("XmlTextNodeLimitExceeded");
                text += length;
                if (text > limits.MaximumTextCharacters) throw new InboundLimitException("XmlTextLimitExceeded");
            }
        }
    }

    private sealed class InboundLimitException : Exception
    {
        internal InboundLimitException(string code) => Code = code;
        internal string Code { get; }
    }
}

internal sealed record SoapReadResult(
    bool IsValid,
    XElement? Operation,
    string? WsAddressingAction,
    string? WsAddressingMessageId,
    string? ErrorCode,
    int MaximumDecodedBinaryBytes)
{
    public static SoapReadResult Valid(XElement operation, string? action, string? messageId,
        int maximumDecodedBinaryBytes) =>
        new(true, operation, action, messageId, null, maximumDecodedBinaryBytes);

    public static SoapReadResult Invalid(string errorCode) => new(false, null, null, null, errorCode,
        InboundRequestLimits.DefaultMaximumDecodedBinaryBytes);
}
