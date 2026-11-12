using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using GatewayUI.Endpoints;
using GatewayUI.Services;
using GatewayUI.Tests.TestSupport;

namespace GatewayUI.Tests.Integration;

public sealed class PaymentEndpointsTests : IClassFixture<GatewayAppFactory>
{
    private readonly GatewayAppFactory _factory;
    private readonly HttpClient _client;

    public PaymentEndpointsTests(GatewayAppFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    private static string UniqueId(string prefix) => prefix + Guid.NewGuid().ToString("N")[..12];

    private static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

    private Task<HttpResponseMessage> PostWebhookAsync(string body, string? signature, string? eventId = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, PaymentEndpoints.WebhookRoute) { Content = Json(body) };
        if (signature is not null)
        {
            request.Headers.Add("X-Razorpay-Signature", signature);
        }
        if (eventId is not null)
        {
            request.Headers.Add("X-Razorpay-Event-Id", eventId);
        }
        return _client.SendAsync(request);
    }

    private static string WebhookBody(string eventName, string paymentId) => TestSecrets.WebhookBody(eventName, paymentId);

    // ----------------------------------------------------------------- order

    [Fact]
    public async Task Order_ReturnsOrderAndPublicKey_ButNeverTheSecret()
    {
        var response = await _client.PostAsJsonAsync(PaymentEndpoints.OrderRoute, new { amount = 50000, currency = "INR" });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var raw = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(TestSecrets.KeySecret, raw);
        using var body = JsonDocument.Parse(raw);
        Assert.Equal("order_stub123", body.RootElement.GetProperty("orderId").GetString());
        Assert.Equal(TestSecrets.KeyId, body.RootElement.GetProperty("keyId").GetString());
    }

    [Theory]
    [InlineData("""{"amount":50,"currency":"INR"}""")]
    [InlineData("""{"amount":99999999999,"currency":"INR"}""")]
    [InlineData("""{"amount":50000,"currency":"USD"}""")]
    public async Task Order_Returns400WithAnErrorMessage_ForInvalidRequests(string body)
    {
        var response = await _client.PostAsync(PaymentEndpoints.OrderRoute, Json(body));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrWhiteSpace(payload.RootElement.GetProperty("error").GetString()));
    }

    [Fact]
    public async Task Order_Returns400_ForMalformedJson()
    {
        var response = await _client.PostAsync(PaymentEndpoints.OrderRoute, Json("{ not json"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---------------------------------------------------------------- verify

    [Fact]
    public async Task Verify_Returns200_ForACorrectSignature_AndWritesTheAuditLog()
    {
        var orderId = UniqueId("order_");
        var paymentId = UniqueId("pay_");

        var response = await _client.PostAsJsonAsync(PaymentEndpoints.VerifyRoute,
            new { orderId, paymentId, signature = TestSecrets.SignPayment(orderId, paymentId) });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<PaymentOperationResult>();
        Assert.True(result!.Ok);
        Assert.Contains(_factory.AuditLines(), line => line.Contains(paymentId) && line.Contains("\"state\":\"verified\""));
    }

    [Fact]
    public async Task Verify_Returns400_ForAForgedSignature()
    {
        var orderId = UniqueId("order_");
        var paymentId = UniqueId("pay_");

        var response = await _client.PostAsJsonAsync(PaymentEndpoints.VerifyRoute,
            new { orderId, paymentId, signature = new string('0', 64) });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<PaymentOperationResult>();
        Assert.False(result!.Ok);
        Assert.Contains(_factory.AuditLines(), line => line.Contains(paymentId) && line.Contains("\"state\":\"rejected\""));
    }

    // --------------------------------------------------------------- webhook

    [Fact]
    public async Task Webhook_Returns401_WhenTheSignatureHeaderIsMissing()
    {
        var response = await PostWebhookAsync(WebhookBody("payment.captured", UniqueId("pay_")), signature: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Webhook_Returns401_ForAnInvalidSignature_AndRecordsNothing()
    {
        var paymentId = UniqueId("pay_");

        var response = await PostWebhookAsync(WebhookBody("payment.captured", paymentId), "deadbeef");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(_factory.AuditLines(), line => line.Contains(paymentId));
    }

    [Fact]
    public async Task Webhook_AcceptsASignedEventOnce_AndSuppressesTheRetry()
    {
        var paymentId = UniqueId("pay_");
        var body = WebhookBody("payment.captured", paymentId);
        var signature = TestSecrets.SignWebhook(body);

        var first = await PostWebhookAsync(body, signature);
        var retry = await PostWebhookAsync(body, signature);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal("Webhook accepted.", (await first.Content.ReadFromJsonAsync<PaymentOperationResult>())!.Message);
        Assert.Equal("Webhook already processed.", (await retry.Content.ReadFromJsonAsync<PaymentOperationResult>())!.Message);
        Assert.Single(_factory.AuditLines(), line => line.Contains(paymentId));
    }

    [Fact]
    public async Task Webhook_RecordsEachLifecycleEventOfOnePayment()
    {
        var paymentId = UniqueId("pay_");
        var authorized = WebhookBody("payment.authorized", paymentId);
        var captured = WebhookBody("payment.captured", paymentId);

        await PostWebhookAsync(authorized, TestSecrets.SignWebhook(authorized));
        await PostWebhookAsync(captured, TestSecrets.SignWebhook(captured));

        Assert.Equal(2, _factory.AuditLines().Count(line => line.Contains(paymentId)));
    }

    [Fact]
    public async Task Webhook_HonoursTheRazorpayEventIdHeader()
    {
        var eventId = UniqueId("evt_");
        var body = WebhookBody("payment.captured", UniqueId("pay_"));

        var response = await PostWebhookAsync(body, TestSecrets.SignWebhook(body), eventId);

        var result = await response.Content.ReadFromJsonAsync<PaymentOperationResult>();
        Assert.Equal(eventId, result!.EventId);
    }

    [Fact]
    public async Task Webhook_Returns400_ForASignedBodyThatIsNotJson()
    {
        const string body = "plain text, correctly signed";

        var response = await PostWebhookAsync(body, TestSecrets.SignWebhook(body));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Webhook_Returns413_ForAnOversizedBody_BeforeCheckingTheSignature()
    {
        var body = new string('x', (int)PaymentEndpoints.MaxWebhookBodyBytes + 1);

        var response = await PostWebhookAsync(body, TestSecrets.SignWebhook(body));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task Webhook_ForwardsAcceptedEventsToTheGoBackend()
    {
        var paymentId = UniqueId("pay_");
        var body = WebhookBody("payment.captured", paymentId);

        await PostWebhookAsync(body, TestSecrets.SignWebhook(body));

        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (!_factory.Http.Requests.Any(r => r.Uri.AbsolutePath == "/payment-event" && r.Body.Contains(paymentId)))
        {
            Assert.True(DateTime.UtcNow < deadline, "accepted webhook was never forwarded to the Go backend");
            await Task.Delay(25);
        }
    }

    // ------------------------------------------------------------ audit file

    [Fact]
    public async Task AuditFile_RemainsAVerifiableHashChain_AfterMixedTraffic()
    {
        for (var i = 0; i < 5; i++)
        {
            var body = WebhookBody("payment.captured", UniqueId("pay_"));
            await PostWebhookAsync(body, TestSecrets.SignWebhook(body));
            var orderId = UniqueId("order_");
            var paymentId = UniqueId("pay_");
            await _client.PostAsJsonAsync(PaymentEndpoints.VerifyRoute,
                new { orderId, paymentId, signature = TestSecrets.SignPayment(orderId, paymentId) });
        }

        var verification = await PaymentAuditService.VerifyFileAsync(_factory.AuditPath);

        Assert.True(verification.Valid, $"payment audit chain broken at line {verification.BrokenAtIndex}");
        Assert.True(verification.Entries >= 10);
    }

    // ----------------------------------------------------------------- pages

    [Fact]
    public async Task UnknownApiRoute_Returns404_NotARewrittenStatus()
    {
        var response = await _client.GetAsync("/api/payments/razorpay/nope");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task HomePage_Renders_WhenTheGoBackendIsUnavailable()
    {
        var response = await _client.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("razorops", await response.Content.ReadAsStringAsync());
    }
}

public sealed class PaymentRateLimitTests : IClassFixture<ThrottledGatewayAppFactory>
{
    private readonly HttpClient _client;

    public PaymentRateLimitTests(ThrottledGatewayAppFactory factory) => _client = factory.CreateClient();

    [Fact]
    public async Task OrderAndVerify_ShareABudget_AndReturn429WhenItIsSpent()
    {
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < ThrottledGatewayAppFactory.Limit + 2; i++)
        {
            var response = await _client.PostAsJsonAsync(PaymentEndpoints.VerifyRoute, new { orderId = "", paymentId = "", signature = "" });
            statuses.Add(response.StatusCode);
        }

        Assert.All(statuses.Take(ThrottledGatewayAppFactory.Limit), status => Assert.Equal(HttpStatusCode.BadRequest, status));
        Assert.All(statuses.Skip(ThrottledGatewayAppFactory.Limit), status => Assert.Equal(HttpStatusCode.TooManyRequests, status));

        var order = await _client.PostAsJsonAsync(PaymentEndpoints.OrderRoute, new { amount = 50000, currency = "INR" });
        Assert.Equal(HttpStatusCode.TooManyRequests, order.StatusCode);
    }

    [Fact]
    public async Task Webhook_IsNotRateLimited()
    {
        for (var i = 0; i < ThrottledGatewayAppFactory.Limit + 5; i++)
        {
            var body = TestSecrets.WebhookBody("payment.captured", $"pay_rl{i}");
            var request = new HttpRequestMessage(HttpMethod.Post, PaymentEndpoints.WebhookRoute)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            request.Headers.Add("X-Razorpay-Signature", TestSecrets.SignWebhook(body));

            var response = await _client.SendAsync(request);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }
}
