using GatewayUI.Endpoints;
using GatewayUI.Tests.TestSupport;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace GatewayUI.Tests.Integration;

/// <summary>
/// Boots the real GatewayUI application in-memory (real routing, middleware,
/// rate limiter and services). Only the edges are replaced: outbound HTTP goes
/// to a stub, the audit file lives in a temp directory, and the background SSE
/// client is not started.
/// </summary>
public class GatewayAppFactory : WebApplicationFactory<Program>
{
    private readonly TempAuditFile _audit = new();

    public StubHttpHandler Http { get; } = StubHttpHandler.Default();

    public string AuditPath => _audit.Path_;

    public string[] AuditLines() => _audit.ReadLines();

    /// <summary>Per-client request budget for the payment endpoints.</summary>
    protected virtual int PaymentRequestsPerMinute => 10_000;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("PaymentAuditPath", _audit.Path_);
        builder.UseSetting(PaymentEndpoints.RequestsPerMinuteSetting, PaymentRequestsPerMinute.ToString());

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IHttpClientFactory>();
            services.AddSingleton<IHttpClientFactory>(new StubHttpClientFactory(Http));
            // The hosted SSE client would keep reconnecting to a Go backend that
            // is not part of these tests.
            services.RemoveAll<IHostedService>();
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _audit.Dispose();
        }
    }
}

/// <summary>Same app with a tiny payment rate limit, to exercise throttling.</summary>
public sealed class ThrottledGatewayAppFactory : GatewayAppFactory
{
    public const int Limit = 3;

    protected override int PaymentRequestsPerMinute => Limit;
}
