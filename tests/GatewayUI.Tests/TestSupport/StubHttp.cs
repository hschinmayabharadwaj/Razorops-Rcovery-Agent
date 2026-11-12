using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace GatewayUI.Tests.TestSupport;

/// <summary>One outbound request captured by <see cref="StubHttpHandler"/>.</summary>
public sealed record RecordedRequest(HttpMethod Method, Uri Uri, string? Authorization, string? ApiKey, string Body);

/// <summary>
/// Stands in for the network: every outbound call (Razorpay API, Go backend)
/// is answered by a test-supplied function and recorded for assertions.
/// </summary>
public sealed class StubHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;
    private readonly ConcurrentQueue<RecordedRequest> _requests = new();

    public StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

    public IReadOnlyCollection<RecordedRequest> Requests => _requests.ToArray();

    public IEnumerable<RecordedRequest> RequestsTo(string host) => Requests.Where(r => r.Uri.Host == host);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        _requests.Enqueue(new RecordedRequest(
            request.Method,
            request.RequestUri!,
            request.Headers.Authorization?.ToString(),
            request.Headers.TryGetValues("X-API-Key", out var keys) ? keys.FirstOrDefault() : null,
            body));
        return _respond(request);
    }

    public static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    /// <summary>
    /// Default behaviour for tests that don't care about outbound calls: a
    /// successful Razorpay order, and an unavailable Go backend.
    /// </summary>
    public static StubHttpHandler Default() => new(request =>
        request.RequestUri!.Host == "api.razorpay.com"
            ? Json(HttpStatusCode.OK, """{"id":"order_stub123","amount":50000,"currency":"INR"}""")
            : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
}

public sealed class StubHttpClientFactory : IHttpClientFactory
{
    private readonly HttpMessageHandler _handler;

    public StubHttpClientFactory(HttpMessageHandler handler) => _handler = handler;

    public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
}
