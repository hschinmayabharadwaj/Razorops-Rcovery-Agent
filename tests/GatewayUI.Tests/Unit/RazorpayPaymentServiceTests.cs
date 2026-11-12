using System.Net;
using System.Text;
using System.Text.Json;
using GatewayUI.Services;
using GatewayUI.Tests.TestSupport;

namespace GatewayUI.Tests.Unit;

public sealed class RazorpayPaymentServiceTests : IDisposable
{
    private readonly TempAuditFile _audit = new();

    public void Dispose() => _audit.Dispose();

    // ---------------------------------------------------------------- orders

    [Theory]
    [InlineData(0)]
    [InlineData(99)]
    [InlineData(-500)]
    public async Task CreateOrder_RejectsAmountBelowMinimum(long amount)
    {
        var http = StubHttpHandler.Default();
        var service = _audit.NewPaymentService(http);

        var (order, error) = await service.CreateOrderAsync(new CreateRazorpayOrderRequest(amount), CancellationToken.None);

        Assert.Null(order);
        Assert.Contains("at least", error);
        Assert.Empty(http.RequestsTo("api.razorpay.com"));
    }

    [Fact]
    public async Task CreateOrder_RejectsAmountAboveCeiling_WithoutCallingRazorpay()
    {
        var http = StubHttpHandler.Default();
        var service = _audit.NewPaymentService(http);

        var (order, error) = await service.CreateOrderAsync(
            new CreateRazorpayOrderRequest(RazorpayPaymentService.MaxOrderAmountPaise + 1), CancellationToken.None);

        Assert.Null(order);
        Assert.Contains("at most", error);
        Assert.Empty(http.RequestsTo("api.razorpay.com"));
    }

    [Fact]
    public async Task CreateOrder_RejectsNonInrCurrency()
    {
        var service = _audit.NewPaymentService();

        var (order, error) = await service.CreateOrderAsync(new CreateRazorpayOrderRequest(50000, "USD"), CancellationToken.None);

        Assert.Null(order);
        Assert.Contains("INR", error);
    }

    [Fact]
    public async Task CreateOrder_RejectsOverlongReceipt()
    {
        var service = _audit.NewPaymentService();
        var receipt = new string('r', RazorpayPaymentService.MaxReceiptLength + 1);

        var (order, error) = await service.CreateOrderAsync(new CreateRazorpayOrderRequest(50000, "INR", receipt), CancellationToken.None);

        Assert.Null(order);
        Assert.Contains("Receipt", error);
    }

    [Fact]
    public async Task CreateOrder_SendsBasicAuthAndReturnsOrderWithPublicKeyOnly()
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.OK, """{"id":"order_abc","amount":50000,"currency":"INR"}"""));
        var service = _audit.NewPaymentService(http);

        var (order, error) = await service.CreateOrderAsync(new CreateRazorpayOrderRequest(50000, "inr"), CancellationToken.None);

        Assert.Null(error);
        Assert.Equal(new RazorpayOrderResponse("order_abc", 50000, "INR", TestSecrets.KeyId), order);

        var request = Assert.Single(http.RequestsTo("api.razorpay.com"));
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/v1/orders", request.Uri.AbsolutePath);
        var expectedBasic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestSecrets.KeyId}:{TestSecrets.KeySecret}"));
        Assert.Equal($"Basic {expectedBasic}", request.Authorization);

        using var sent = JsonDocument.Parse(request.Body);
        Assert.Equal(50000, sent.RootElement.GetProperty("amount").GetInt64());
        Assert.Equal("INR", sent.RootElement.GetProperty("currency").GetString());
        Assert.StartsWith("rcpt_", sent.RootElement.GetProperty("receipt").GetString());
    }

    [Fact]
    public async Task CreateOrder_ReportsRazorpayFailureStatusWithoutLeakingBody()
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.Unauthorized, """{"error":{"description":"secret internal detail"}}"""));
        var service = _audit.NewPaymentService(http);

        var (order, error) = await service.CreateOrderAsync(new CreateRazorpayOrderRequest(50000), CancellationToken.None);

        Assert.Null(order);
        Assert.Contains("401", error);
        Assert.DoesNotContain("secret internal detail", error);
    }

    [Fact]
    public async Task CreateOrder_HidesExceptionDetailsFromCaller()
    {
        var http = new StubHttpHandler(_ => throw new HttpRequestException("connection refused to 10.0.0.7:443"));
        var service = _audit.NewPaymentService(http);

        var (order, error) = await service.CreateOrderAsync(new CreateRazorpayOrderRequest(50000), CancellationToken.None);

        Assert.Null(order);
        Assert.NotNull(error);
        Assert.DoesNotContain("10.0.0.7", error);
    }

    // ---------------------------------------------------------------- verify

    [Fact]
    public async Task VerifyPayment_AcceptsCorrectSignatureAndAuditsIt()
    {
        var service = _audit.NewPaymentService();
        var signature = TestSecrets.SignPayment("order_1", "pay_1");

        var result = await service.VerifyPaymentAsync(new VerifyRazorpayPaymentRequest("order_1", "pay_1", signature), CancellationToken.None);

        Assert.True(result.Ok);
        Assert.Equal("payment.verified.pay_1", result.EventId);
        var line = Assert.Single(_audit.ReadLines());
        Assert.Contains("\"state\":\"verified\"", line);
    }

    [Fact]
    public async Task VerifyPayment_RejectsWrongSignatureAndAuditsTheRejection()
    {
        var service = _audit.NewPaymentService();
        var signatureForAnotherPayment = TestSecrets.SignPayment("order_1", "pay_OTHER");

        var result = await service.VerifyPaymentAsync(new VerifyRazorpayPaymentRequest("order_1", "pay_1", signatureForAnotherPayment), CancellationToken.None);

        Assert.False(result.Ok);
        var line = Assert.Single(_audit.ReadLines());
        Assert.Contains("\"state\":\"rejected\"", line);
    }

    [Theory]
    [InlineData("", "pay_1", "sig")]
    [InlineData("order_1", " ", "sig")]
    [InlineData("order_1", "pay_1", "")]
    public async Task VerifyPayment_RequiresAllFields(string orderId, string paymentId, string signature)
    {
        var service = _audit.NewPaymentService();

        var result = await service.VerifyPaymentAsync(new VerifyRazorpayPaymentRequest(orderId, paymentId, signature), CancellationToken.None);

        Assert.False(result.Ok);
        Assert.Empty(_audit.ReadLines());
    }

    [Theory]
    [InlineData("order_1\n{\"forged\":true}", "pay_1")]
    [InlineData("order_1", "pay_<script>")]
    [InlineData("order_1", "pay with spaces")]
    public async Task VerifyPayment_RejectsMalformedIdentifiersBeforeAuditing(string orderId, string paymentId)
    {
        var service = _audit.NewPaymentService();

        var result = await service.VerifyPaymentAsync(new VerifyRazorpayPaymentRequest(orderId, paymentId, "abc"), CancellationToken.None);

        Assert.False(result.Ok);
        Assert.Contains("malformed", result.Message);
        Assert.Empty(_audit.ReadLines());
    }

    [Fact]
    public async Task VerifyPayment_RejectsOverlongIdentifiers()
    {
        var service = _audit.NewPaymentService();
        var longId = "pay_" + new string('a', RazorpayPaymentService.MaxIdentifierLength);

        var result = await service.VerifyPaymentAsync(new VerifyRazorpayPaymentRequest("order_1", longId, "abc"), CancellationToken.None);

        Assert.False(result.Ok);
        Assert.Empty(_audit.ReadLines());
    }

    // --------------------------------------------------------------- webhook

    private static string WebhookBody(string eventName, string paymentId) => TestSecrets.WebhookBody(eventName, paymentId);

    [Fact]
    public async Task Webhook_RejectsInvalidSignature_AndRecordsNothing()
    {
        var service = _audit.NewPaymentService();
        var body = WebhookBody("payment.captured", "pay_1");

        var result = await service.ProcessWebhookAsync("deadbeef", body, null, CancellationToken.None);

        Assert.False(result.Ok);
        Assert.Empty(_audit.ReadLines());
    }

    [Fact]
    public async Task Webhook_RejectsBodyTamperedAfterSigning()
    {
        var service = _audit.NewPaymentService();
        var signature = TestSecrets.SignWebhook(WebhookBody("payment.captured", "pay_1"));

        var result = await service.ProcessWebhookAsync(signature, WebhookBody("payment.captured", "pay_2"), null, CancellationToken.None);

        Assert.False(result.Ok);
    }

    [Fact]
    public async Task Webhook_AcceptsValidEventOnce_AndSuppressesTheRetry()
    {
        var service = _audit.NewPaymentService();
        var body = WebhookBody("payment.captured", "pay_1");
        var signature = TestSecrets.SignWebhook(body);

        var first = await service.ProcessWebhookAsync(signature, body, null, CancellationToken.None);
        var retry = await service.ProcessWebhookAsync(signature, body, null, CancellationToken.None);

        Assert.True(first.Ok);
        Assert.Equal("Webhook accepted.", first.Message);
        Assert.True(retry.Ok);
        Assert.Equal("Webhook already processed.", retry.Message);
        Assert.Single(_audit.ReadLines());
    }

    [Fact]
    public async Task Webhook_TreatsDifferentEventsForTheSamePaymentAsDistinct()
    {
        var service = _audit.NewPaymentService();
        var authorized = WebhookBody("payment.authorized", "pay_1");
        var captured = WebhookBody("payment.captured", "pay_1");

        var first = await service.ProcessWebhookAsync(TestSecrets.SignWebhook(authorized), authorized, null, CancellationToken.None);
        var second = await service.ProcessWebhookAsync(TestSecrets.SignWebhook(captured), captured, null, CancellationToken.None);

        Assert.Equal("Webhook accepted.", first.Message);
        Assert.Equal("Webhook accepted.", second.Message);
        Assert.NotEqual(first.EventId, second.EventId);
        Assert.Equal(2, _audit.ReadLines().Length);
    }

    [Fact]
    public async Task Webhook_UsesRazorpayEventIdHeaderAsIdempotencyKey()
    {
        var service = _audit.NewPaymentService();
        var body = WebhookBody("payment.captured", "pay_1");
        var signature = TestSecrets.SignWebhook(body);

        var first = await service.ProcessWebhookAsync(signature, body, "evt_A", CancellationToken.None);
        var sameEvent = await service.ProcessWebhookAsync(signature, body, "evt_A", CancellationToken.None);
        var newEvent = await service.ProcessWebhookAsync(signature, body, "evt_B", CancellationToken.None);

        Assert.Equal("evt_A", first.EventId);
        Assert.Equal("Webhook already processed.", sameEvent.Message);
        Assert.Equal("Webhook accepted.", newEvent.Message);
    }

    [Fact]
    public async Task Webhook_IgnoresUnsafeEventIdHeader()
    {
        var service = _audit.NewPaymentService();
        var body = WebhookBody("payment.captured", "pay_1");

        var result = await service.ProcessWebhookAsync(TestSecrets.SignWebhook(body), body, "evt\r\n\"injected\"", CancellationToken.None);

        Assert.True(result.Ok);
        Assert.Equal("payment.captured:pay_1", result.EventId);
    }

    [Fact]
    public async Task Webhook_WithoutPaymentEntity_DeduplicatesOnBodyHash()
    {
        var service = _audit.NewPaymentService();
        const string body = """{"event":"order.paid","payload":{}}""";
        var signature = TestSecrets.SignWebhook(body);

        var first = await service.ProcessWebhookAsync(signature, body, null, CancellationToken.None);
        var retry = await service.ProcessWebhookAsync(signature, body, null, CancellationToken.None);

        Assert.StartsWith("webhook.", first.EventId);
        Assert.Equal(first.EventId, retry.EventId);
        Assert.Equal("Webhook already processed.", retry.Message);
    }

    [Fact]
    public async Task Webhook_ThrowsJsonException_ForSignedNonJsonBody()
    {
        var service = _audit.NewPaymentService();
        const string body = "this is not json";

        await Assert.ThrowsAnyAsync<JsonException>(() =>
            service.ProcessWebhookAsync(TestSecrets.SignWebhook(body), body, null, CancellationToken.None));
    }

    [Fact]
    public async Task Webhook_ReleasesIdempotencyClaim_WhenAuditWriteFails()
    {
        var service = _audit.NewPaymentService();
        var body = WebhookBody("payment.captured", "pay_1");
        var signature = TestSecrets.SignWebhook(body);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        // First delivery cannot be recorded (the audit append is cancelled) ...
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.ProcessWebhookAsync(signature, body, null, cancelled.Token));

        // ... so Razorpay's retry must be processed, not reported as a duplicate.
        var retry = await service.ProcessWebhookAsync(signature, body, null, CancellationToken.None);
        Assert.Equal("Webhook accepted.", retry.Message);
        Assert.Single(_audit.ReadLines());
    }
}
