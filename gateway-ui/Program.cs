using GatewayUI.Components;
using GatewayUI.Endpoints;
using GatewayUI.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddHttpClient();
builder.Services.AddSingleton<IGatewayApi, GatewayApiService>();
builder.Services.AddSingleton<AuditStreamService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<AuditStreamService>());
builder.Services.AddSingleton<PaymentAuditService>();
builder.Services.AddSingleton<RazorpayPaymentService>();
builder.Services.AddPaymentRateLimiting();

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
app.MapPaymentEndpoints();

app.Run();

// Exposes the entry point to the integration tests (WebApplicationFactory<Program>).
public partial class Program;
