using System.Text.Json;
using System.Threading.RateLimiting;
using GatewayUI.Components;
using GatewayUI.Services;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;

// Razorpay webhook payloads are a few KB; 1 MB is a generous ceiling.
const long MaxWebhookBodyBytes = 1024 * 1024;
const string PaymentsRateLimitPolicy = "payments";
const int PaymentsRequestsPerMinute = 20;
const string PaymentsUnavailable = "Payments are not available right now.";

var builder = WebApplication.CreateBuilder(args);

// The order/verify endpoints are anonymous and call the merchant's Razorpay
// account, so cap how often a single client address can hit them.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(PaymentsRateLimitPolicy, context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = PaymentsRequestsPerMinute,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
});

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddHttpClient();
builder.Services.AddSingleton<IGatewayApi, GatewayApiService>();
builder.Services.AddSingleton<AuditStreamService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<AuditStreamService>());
builder.Services.AddSingleton<PaymentAuditService>();
builder.Services.AddSingleton<RazorpayPaymentService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
// Friendly status pages are for browser page requests only. Re-executing an
// API or webhook response would replace its real status (401/413/429) with the
// status of the re-executed page request.
app.UseWhen(
    context => !context.Request.Path.StartsWithSegments("/api") && !context.Request.Path.StartsWithSegments("/webhooks"),
    pages => pages.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true));
app.UseHttpsRedirection();

app.UseAntiforgery();
app.UseRateLimiter();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapPost("/api/payments/razorpay/order", async (CreateRazorpayOrderRequest request, RazorpayPaymentService payments, CancellationToken cancellationToken) =>
{
    try
    {
        var result = await payments.CreateOrderAsync(request, cancellationToken);
        return result.Order is null
            ? Results.BadRequest(new { error = result.Error })
            : Results.Ok(result.Order);
    }
    catch (InvalidOperationException ex)
    {
        app.Logger.LogError(ex, "Razorpay order endpoint is not configured");
        return Results.Problem(PaymentsUnavailable, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
}).RequireRateLimiting(PaymentsRateLimitPolicy);

app.MapPost("/api/payments/razorpay/verify", async (VerifyRazorpayPaymentRequest request, RazorpayPaymentService payments, CancellationToken cancellationToken) =>
{
    try
    {
        var result = await payments.VerifyPaymentAsync(request, cancellationToken);
        return result.Ok ? Results.Ok(result) : Results.BadRequest(result);
    }
    catch (InvalidOperationException ex)
    {
        app.Logger.LogError(ex, "Razorpay verify endpoint is not configured");
        return Results.Problem(PaymentsUnavailable, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
}).RequireRateLimiting(PaymentsRateLimitPolicy);

app.MapPost("/webhooks/razorpay", async (HttpRequest request, RazorpayPaymentService payments, CancellationToken cancellationToken) =>
{
    var signature = request.Headers["X-Razorpay-Signature"].ToString();
    if (string.IsNullOrWhiteSpace(signature))
    {
        return Results.Unauthorized();
    }

    // Bound the body BEFORE reading it: it is buffered in full ahead of the
    // HMAC check, so an unbounded body is a memory-exhaustion vector.
    if (request.ContentLength is > MaxWebhookBodyBytes)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }
    var sizeFeature = request.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (sizeFeature is { IsReadOnly: false })
    {
        sizeFeature.MaxRequestBodySize = MaxWebhookBodyBytes;
    }

    string rawBody;
    try
    {
        using var reader = new StreamReader(request.Body);
        rawBody = await reader.ReadToEndAsync(cancellationToken);
    }
    catch (BadHttpRequestException)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }

    var razorpayEventId = request.Headers["X-Razorpay-Event-Id"].ToString();
    try
    {
        var result = await payments.ProcessWebhookAsync(signature, rawBody, razorpayEventId, cancellationToken);
        return result.Ok ? Results.Ok(result) : Results.Unauthorized();
    }
    catch (JsonException)
    {
        return Results.BadRequest(new { error = "Webhook body is not valid JSON." });
    }
    catch (InvalidOperationException ex)
    {
        app.Logger.LogError(ex, "Razorpay webhook could not be processed");
        return Results.Problem(PaymentsUnavailable, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.Run();
