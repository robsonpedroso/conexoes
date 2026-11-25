using System.Collections.Concurrent;
using System.Net;

namespace Conexoes.Core.Net;

/// <summary>DNS reverso assíncrono com cache, limite de concorrência e timeout.</summary>
public sealed class ReverseDnsCache
{
    private readonly ConcurrentDictionary<IPAddress, Task<string?>> _cache = new();
    private readonly SemaphoreSlim _gate = new(8);
    private readonly TimeSpan _timeout = TimeSpan.FromSeconds(3);

    public bool TryGetCached(IPAddress ip, out string? name)
    {
        name = null;
        if (_cache.TryGetValue(ip, out var t) && t.IsCompletedSuccessfully)
        {
            name = t.Result;
            return true;
        }
        return false;
    }

    public Task<string?> ResolveAsync(IPAddress ip) => _cache.GetOrAdd(ip, Lookup);

    private async Task<string?> Lookup(IPAddress ip)
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip).WaitAsync(_timeout).ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(entry.HostName) || entry.HostName == ip.ToString() ? "" : entry.HostName;
        }
        catch
        {
            return "";
        }
        finally
        {
            _gate.Release();
        }
    }
}
