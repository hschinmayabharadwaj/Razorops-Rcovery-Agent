using System.Net.Http.Headers;
using System.Net;
using System.Text.Json;
using GatewayUI.Models;

namespace GatewayUI.Services;

// AuditStreamService is a singleton (Blazor Server host) that maintains ONE
// server-side streaming SSE connection to the Go /events endpoint and fans each
// parsed entry out to subscribed circuits. Blazor Server's built-in SignalR
// circuit is what pushes any resulting StateHasChanged() to the browser — no
// separate Hub is required. It reconnects with backoff when the stream drops
// and surfaces a "reconnecting..." state instead of going silently stale.
public class AuditStreamService : IHostedService
{
    public const int ReconnectDelayMs = 2500;
    public const int MaxBuffered = 500;

    private readonly IGatewayApi _api;
    private readonly IHttpClientFactory _factory;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private readonly Dictionary<long, Action<StreamEvent>> _subscribers = new();
    private long _nextId;
    private readonly List<StreamEvent> _buffer = new();
    private const int MaxSeenHashes = 100_000;
    private readonly HashSet<string> _seenHashes = new(StringComparer.Ordinal);

    public string BaseUrl => _api.BaseUrl;

    public event Action<StreamStatus>? StatusChanged;

    private StreamPhase _phase = StreamPhase.Connecting;
    private string _detail = "not started";
    private Task? _loop;

    public StreamStatus CurrentStatus => new(_phase, _detail);

    public AuditStreamService(IGatewayApi api, IHttpClientFactory factory)
    {
        _api = api;
        _factory = factory;
    }

    public long Subscribe(Action<StreamEvent> handler)
    {
        lock (_gate)
        {
            var id = _nextId++;
            _subscribers[id] = handler;
            // Replay any events that arrived before this subscriber connected
            // (e.g. the history replayed when the singleton stream first opened),
            // so a late-joining page still sees the full audit history.
            foreach (var ev in _buffer)
            {
                try
                {
                    handler(ev);
                }
                catch
                {
                    // a handler must never break subscription
                }
            }
            return id;
        }
    }

    public void Unsubscribe(long id)
    {
        lock (_gate)
        {
            _subscribers.Remove(id);
        }
    }

    private void SetStatus(StreamPhase phase, string detail)
    {
        lock (_gate)
        {
            _phase = phase;
            _detail = detail;
        }
        StatusChanged?.Invoke(new StreamStatus(phase, detail));
    }

    private void Publish(StreamEvent ev)
    {
        Action<StreamEvent>[] snap;
        lock (_gate)
        {
            // The Go server replays the full history on every (re)connect. Each
            // audit entry's chain hash is unique, so skip rows already published
            // instead of showing every row again after a reconnect.
            if (ev is AuditStreamEvent { Entry.Hash: { Length: > 0 } hash })
            {
                if (_seenHashes.Count >= MaxSeenHashes)
                {
                    _seenHashes.Clear();
                }
                if (!_seenHashes.Add(hash))
                {
                    return;
                }
            }
            _buffer.Add(ev);
            while (_buffer.Count > MaxBuffered)
            {
                _buffer.RemoveAt(0);
            }
            snap = _subscribers.Values.ToArray();
        }
        foreach (var handler in snap)
        {
            try
            {
                handler(ev);
            }
            catch
            {
                // a handler must never kill the stream loop
            }
        }
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        SetStatus(StreamPhase.Connecting, "connecting");
        _loop = Task.Run(() => RunLoopAsync(_cts.Token), CancellationToken.None);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _cts.Cancel();
        try
        {
            _loop?.Wait(TimeSpan.FromSeconds(3));
        }
        catch
        {
            // ignore teardown
        }
        return Task.CompletedTask;
    }

    private async Task RunLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var client = _factory.CreateClient();
                client.Timeout = Timeout.InfiniteTimeSpan;
                using var req = _api.NewRequest(HttpMethod.Get, "/events");
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

                using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);

                if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                {
                    SetStatus(StreamPhase.Denied, "insufficient permissions for the audit stream (HTTP " + (int)resp.StatusCode + ")");
                    await Task.Delay(ReconnectDelayMs, ct);
                    continue;
                }

                resp.EnsureSuccessStatusCode();
                SetStatus(StreamPhase.Connected, "connected");

                using var stream = await resp.Content.ReadAsStreamAsync(ct);
                using var reader = new StreamReader(stream);
                string? line;
                while ((line = await reader.ReadLineAsync(ct)) != null)
                {
                    if (!line.StartsWith("data:", StringComparison.Ordinal))
                    {
                        continue;
                    }
                    var payload = line.Substring(5).Trim();
                    if (payload.Length == 0)
                    {
                        continue;
                    }
                    var ev = ParseEvent(payload);
                    if (ev != null)
                    {
                        Publish(ev);
                    }
                }

                // Stream ended cleanly (server closed it) -> reconnect.
                if (!ct.IsCancellationRequested)
                {
                    SetStatus(StreamPhase.Reconnecting, "stream ended; reconnecting");
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested)
                {
                    return;
                }
                SetStatus(StreamPhase.Reconnecting, "reconnecting: " + ex.Message);
            }

            await Task.Delay(ReconnectDelayMs, ct);
        }
    }

    private static StreamEvent? ParseEvent(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var type = root.TryGetProperty("eventType", out var t) ? t.GetString() : "audit";

            if (type == "chain_status")
            {
                var valid = root.TryGetProperty("valid", out var v) && v.GetBoolean();
                var entries = root.TryGetProperty("entries", out var en) ? en.GetInt32() : 0;
                var brokenAt = (root.TryGetProperty("brokenAt", out var b) && b.ValueKind == JsonValueKind.Number)
                    ? (int?)b.GetInt32()
                    : null;
                return new ChainStatusStreamEvent(new ChainStatusDto(valid, entries, brokenAt));
            }

            var entry = JsonSerializer.Deserialize<AuditEntryDto>(json);
            return entry == null ? null : new AuditStreamEvent(entry);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
