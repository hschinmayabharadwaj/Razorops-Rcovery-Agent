[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace GatewayUI.E2E;

/// <summary>
/// Browser end-to-end tests start the Go backend, the Blazor app and a real
/// browser, so they only run when asked for: set RUN_E2E=1. Without it they
/// are reported as skipped, with the reason, rather than silently absent.
/// </summary>
public sealed class E2EFactAttribute : FactAttribute
{
    public const string SwitchVariable = "RUN_E2E";

    public E2EFactAttribute()
    {
        if (Environment.GetEnvironmentVariable(SwitchVariable) != "1")
        {
            Skip = $"Browser E2E tests are opt-in: set {SwitchVariable}=1 (needs Go, and Edge/Chrome or Playwright's Chromium).";
        }
    }
}
