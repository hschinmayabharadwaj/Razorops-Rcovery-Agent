using System.Text.RegularExpressions;
using Microsoft.Playwright;
using static Microsoft.Playwright.Assertions;

namespace GatewayUI.E2E;

/// <summary>
/// Critical user journeys through the real dashboard in a real browser, backed
/// by the real Go engine running the canonical batch.
/// </summary>
public sealed class DashboardJourneyTests : IClassFixture<E2EStack>
{
    private readonly E2EStack _stack;

    public DashboardJourneyTests(E2EStack stack) => _stack = stack;

    [E2EFact]
    public async Task Overview_ShowsRecoveryMetricsAndAnIntactChain()
    {
        var page = await _stack.NewPageAsync();

        await page.GotoAsync("/");

        await Expect(page).ToHaveTitleAsync(new Regex("Overview"));
        // Recovery figures come from the Go engine, not placeholders.
        await Expect(page.Locator(".stat-card-featured .stat-value")).ToContainTextAsync("₹");
        await Expect(page.Locator(".stat-card-featured .stat-value")).Not.ToHaveTextAsync(new Regex(@"^₹\s?0$"));
        await Expect(page.GetByText("Audit hash chain is intact")).ToBeVisibleAsync();
        await Expect(page.GetByText(new Regex(@"[1-9]\d* entries cryptographically verified"))).ToBeVisibleAsync();
        // The flow breakdown lists the engine's recovery flows.
        await Expect(page.Locator(".flow-bar-item")).ToHaveCountAsync(7);
    }

    [E2EFact]
    public async Task LiveAudit_StreamsTheFullAuditHistory()
    {
        var page = await _stack.NewPageAsync();

        await page.GotoAsync("/liveaudit");

        await Expect(page.Locator("#live-status .badge")).ToContainTextAsync("connected");
        await Expect(page.GetByText(new Regex(@"Chain Verified, [1-9]\d* entries"))).ToBeVisibleAsync();
        // The canonical batch writes well over a hundred audit rows.
        await Expect(page.Locator("tr.audit-row").Nth(100)).ToBeAttachedAsync();
        // Every row names the rule that fired — decisions are never anonymous.
        await Expect(page.Locator("tr.audit-row").First.Locator(".badge.bg-secondary")).Not.ToBeEmptyAsync();
    }

    [E2EFact]
    public async Task AdminNudge_OnAFraudEvent_IsRefusedByTheLockedRule()
    {
        var page = await _stack.NewPageAsync();
        await page.GotoAsync("/liveaudit");
        var fraudRow = page.Locator("tr.audit-row", new PageLocatorOptions { HasText = "fraud_suppress" }).First;
        await Expect(fraudRow).ToBeAttachedAsync();

        // Selecting a row needs the interactive circuit; retry until it is live.
        var panel = page.Locator(".card", new PageLocatorOptions { HasText = "Admin Intervention" });
        await RetryUntilVisibleAsync(() => fraudRow.ClickAsync(), panel);

        await panel.GetByRole(AriaRole.Button, new LocatorGetByRoleOptions { Name = "Nudge Retry Now" }).ClickAsync();

        var refusal = panel.Locator(".alert-warning");
        await Expect(refusal).ToContainTextAsync("Refused.");
        await Expect(refusal).ToContainTextAsync("fraud_suppress");
        // The refusal itself is audited and attributed to the admin.
        await Expect(page.Locator("tr.audit-row", new PageLocatorOptions { HasText = "REFUSED:" }).Last).ToContainTextAsync("admin:admin-demo");
    }

    [E2EFact]
    public async Task Exceptions_ListsTheHumanReviewQueue_WithRedactedCustomers()
    {
        var page = await _stack.NewPageAsync();

        await page.GotoAsync("/exceptions");

        await Expect(page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Human review queue" })).ToBeVisibleAsync();
        var customerCells = page.Locator("tbody tr td:nth-child(3)");
        await Expect(customerCells.First).ToBeVisibleAsync();
        var customers = await customerCells.AllInnerTextsAsync();
        Assert.NotEmpty(customers);
        Assert.All(customers.Where(c => !string.IsNullOrWhiteSpace(c)), c => Assert.Contains("•••", c));
    }

    public static TheoryData<string, string> Pages => new()
    {
        { "/metrics", "Recovery Metrics" },
        { "/compare-policy", "Real policy vs naive baseline" },
        { "/prescore", "Risk Prescore (predict-before-fail)" },
        { "/sandbox", "Backtest sandbox (tunable sweep)" },
        { "/recovery", "Recovery Progress" },
    };

    [E2ETheory]
    [MemberData(nameof(Pages))]
    public async Task Page_LoadsItsDataFromTheBackend_WithoutErrors(string path, string heading)
    {
        var page = await _stack.NewPageAsync();

        await page.GotoAsync(path);

        await Expect(page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = heading, Exact = true })).ToBeVisibleAsync();
        await Expect(page.GetByText("Loading…")).ToHaveCountAsync(0);
        await Expect(page.GetByText("Could not reach the backend")).ToHaveCountAsync(0);
        await Expect(page.GetByText("Insufficient permissions")).ToHaveCountAsync(0);
        await Expect(page.Locator("#blazor-error-ui")).ToBeHiddenAsync();
    }

    private static async Task RetryUntilVisibleAsync(Func<Task> action, ILocator target)
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            await action();
            try
            {
                await Expect(target).ToBeVisibleAsync(new LocatorAssertionsToBeVisibleOptions { Timeout = 1_000 });
                return;
            }
            catch (PlaywrightException)
            {
                // circuit not interactive yet; try again
            }
        }
        await Expect(target).ToBeVisibleAsync();
    }
}

/// <summary>
/// The tamper demo flips the shared chain status for every open page, so it
/// runs against its own stack.
/// </summary>
public sealed class TamperDemoTests : IClassFixture<E2EStack>
{
    private readonly E2EStack _stack;

    public TamperDemoTests(E2EStack stack) => _stack = stack;

    [E2EFact]
    public async Task SimulateTamper_FlipsTheChainBadgeToBroken()
    {
        var page = await _stack.NewPageAsync();
        await page.GotoAsync("/liveaudit");
        await Expect(page.GetByText(new Regex(@"Chain Verified, [1-9]\d* entries"))).ToBeVisibleAsync();
        var broken = page.GetByText("Chain Broken at entry 0");

        // The button needs the interactive circuit; retry until the badge flips.
        var tamper = page.GetByRole(AriaRole.Button, new PageGetByRoleOptions { Name = "Simulate Tamper (Sandbox Only)" });
        for (var attempt = 0; attempt < 20 && !await broken.IsVisibleAsync(); attempt++)
        {
            await tamper.ClickAsync();
            await page.WaitForTimeoutAsync(500);
        }

        await Expect(broken).ToBeVisibleAsync();
        // The demo tampers an in-memory copy: the real log still verifies.
        using var http = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, _stack.GoUrl + "/chain-status");
        request.Headers.Add("X-API-Key", "admin_key_demo");
        using var response = await http.SendAsync(request);
        Assert.Contains("\"valid\":true", await response.Content.ReadAsStringAsync());
    }
}

/// <summary>Theory counterpart of <see cref="E2EFactAttribute"/>.</summary>
public sealed class E2ETheoryAttribute : TheoryAttribute
{
    public E2ETheoryAttribute()
    {
        if (Environment.GetEnvironmentVariable(E2EFactAttribute.SwitchVariable) != "1")
        {
            Skip = $"Browser E2E tests are opt-in: set {E2EFactAttribute.SwitchVariable}=1.";
        }
    }
}
