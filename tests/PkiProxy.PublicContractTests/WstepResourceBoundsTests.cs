using System.Xml.Linq;
using PkiProxy.Protocol.Wstep;

internal static class WstepResourceBoundsTests
{
    private static readonly XNamespace Wst = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
    private static readonly XNamespace Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static readonly XNamespace Wstep = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
    private const string TokenType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    private const string Base64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";

    public static void Run()
    {
        var issue = Request("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
            new XElement(Wsse + "BinarySecurityToken", new XAttribute("EncodingType", Base64), "AQID"));
        Check(WstepRequestContract.TryParse(issue, WstepRequestContract.EnrollmentAction, out var parsed, out _)
            && parsed!.CertificateRequestDer!.SequenceEqual(new byte[] { 1, 2, 3 }), "small Issue remains accepted");
        issue.SetAttributeValue("Context", new string('c', WstepRequestContract.MaximumContextLength));
        Check(WstepRequestContract.TryParse(issue, WstepRequestContract.EnrollmentAction, out _, out _), "Context boundary accepted");
        issue.SetAttributeValue("Context", new string('c', WstepRequestContract.MaximumContextLength + 1));
        Check(!WstepRequestContract.TryParse(issue, WstepRequestContract.EnrollmentAction, out _, out var error)
            && error == "InvalidWstepContext", "Context boundary plus one rejected");
        issue.SetAttributeValue("Context", " c");
        Check(!WstepRequestContract.TryParse(issue, WstepRequestContract.EnrollmentAction, out _, out _), "Context whitespace ambiguity rejected");
        issue.SetAttributeValue("Context", "c\u0001");
        Check(!WstepRequestContract.TryParse(issue, WstepRequestContract.EnrollmentAction, out _, out _), "Context control rejected");

        var query = Request("http://schemas.microsoft.com/windows/pki/2009/01/enrollment/QueryTokenStatus",
            new XElement(Wstep + "RequestID", new string('r', WstepRequestContract.MaximumRequestIdLength)));
        Check(WstepRequestContract.TryParse(query, WstepRequestContract.EnrollmentAction, out parsed, out _)
            && parsed!.RequestId == new string('r', WstepRequestContract.MaximumRequestIdLength), "RequestID boundary and exact text accepted");
        query.Element(Wstep + "RequestID")!.Value = new string('r', WstepRequestContract.MaximumRequestIdLength + 1);
        Check(!WstepRequestContract.TryParse(query, WstepRequestContract.EnrollmentAction, out _, out _), "RequestID boundary plus one rejected");
        foreach (var value in new[] { "", " ", " r", "r ", "r\u0001" })
        {
            query.Element(Wstep + "RequestID")!.Value = value;
            Check(!WstepRequestContract.TryParse(query, WstepRequestContract.EnrollmentAction, out _, out _), "ambiguous RequestID rejected");
        }

        var ket = Request("http://docs.oasis-open.org/ws-sx/ws-trust/200512/KET", new XElement(Wst + "RequestKET"));
        Check(WstepRequestContract.TryParse(ket, WstepRequestContract.KetAction, out parsed, out _)
            && parsed!.Kind == WstepRequestKind.KeyExchangeToken, "KET remains accepted");
        ket.Add(new XElement((XNamespace)"urn:ignored" + "Extension", "ignored"));
        Check(WstepRequestContract.TryParse(ket, WstepRequestContract.KetAction, out _, out _), "unrelated extension remains ignored");

        var spaced = Request("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
            new XElement(Wsse + "BinarySecurityToken", new XAttribute("EncodingType", Base64), " AQ\nID\t"));
        Check(WstepRequestContract.TryParse(spaced, WstepRequestContract.EnrollmentAction, out parsed, out _)
            && parsed!.CertificateRequestDer!.SequenceEqual(new byte[] { 1, 2, 3 }), "base64 XML whitespace remains accepted");
        var oversized = Request("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
            new XElement(Wsse + "BinarySecurityToken", new XAttribute("EncodingType", Base64), Convert.ToBase64String(new byte[WstepRequestContract.MaximumBinaryTokenBytes + 1])));
        Check(!WstepRequestContract.TryParse(oversized, WstepRequestContract.EnrollmentAction, out _, out _), "oversized token rejected");
        var exactToken = Request("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
            new XElement(Wsse + "BinarySecurityToken", new XAttribute("EncodingType", Base64), Convert.ToBase64String(new byte[WstepRequestContract.MaximumBinaryTokenBytes])));
        Check(WstepRequestContract.TryParse(exactToken, WstepRequestContract.EnrollmentAction, out parsed, out _)
            && parsed!.CertificateRequestDer!.Length == WstepRequestContract.MaximumBinaryTokenBytes, "token byte boundary accepted");
        var malformed = Request("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
            new XElement(Wsse + "BinarySecurityToken", new XAttribute("EncodingType", Base64), "!!!"));
        Check(!WstepRequestContract.TryParse(malformed, WstepRequestContract.EnrollmentAction, out _, out _), "malformed token rejected");

        CheckThrows(() => WstepResponseWriter.CreatePending(" ", "en-GB"));
        CheckThrows(() => WstepResponseWriter.CreatePending(null!, "en-GB"));
        CheckThrows(() => WstepResponseWriter.CreatePending("x\u0001", "en-GB"));
        CheckThrows(() => WstepResponseWriter.CreatePending("exact", " en-GB"));
        CheckThrows(() => WstepResponseWriter.CreateIssued([1], [2], new string('r', WstepRequestContract.MaximumRequestIdLength + 1), "en-GB"));
        CheckThrows(() => WstepResponseWriter.CreateIssued(new byte[65_537], [2], "id", "en-GB"));
        CheckThrows(() => WstepResponseWriter.CreateIssued([1], new byte[786_433], "id", "en-GB"));
        Check(WstepResponseWriter.CreateIssued(new byte[65_536], new byte[786_432], "id", "en-GB")
            .Descendants(Wstep + "RequestID").Single().Value == "id", "response byte boundaries accepted");
        var nil = WstepResponseWriter.CreateIssued([1], [2], null, "en-GB");
        Check((string?)nil.Descendants(Wstep + "RequestID").Single().Attribute(XNamespace.Xmlns + "nil") is null &&
            (string?)nil.Descendants(Wstep + "RequestID").Single().Attribute((XNamespace)"http://www.w3.org/2001/XMLSchema-instance" + "nil") == "true", "null issuer RequestID remains explicitly nil");
        Check(WstepResponseWriter.CreatePending("exact", "en-GB").Descendants(Wstep + "RequestID").Single().Value == "exact", "pending response preserves RequestID");
    }

    private static XElement Request(string requestType, params object[] children) => new(Wst + "RequestSecurityToken",
        new XElement(Wst + "TokenType", TokenType), new XElement(Wst + "RequestType", requestType), children);
    private static void Check(bool condition, string message) { if (!condition) throw new InvalidOperationException(message); }
    private static void CheckThrows(Action action) { try { action(); } catch (ArgumentException) { return; } throw new InvalidOperationException("expected bounded response argument rejection"); }
}
