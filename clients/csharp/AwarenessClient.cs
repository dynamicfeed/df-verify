// AwarenessClient.cs — QUARANTINED transport-only C# sample.
//
// This file does NOT implement DF-VERIFY/1 canonicalization, key-id binding, signing-key
// lifecycle validation, or registry anti-rollback. It therefore MUST NOT return an actionable
// verdict and is not a reference verifier. Use the Python, JavaScript, or Rust implementation
// until a conformance-tested C# lifecycle-aware verifier exists.

using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DynamicFeed
{
    /// <summary>
    /// Transport-only access to an unverified awareness response. No method in this class may be
    /// used to authorize physical actuation, trading, filing, or another consequential action.
    /// </summary>
    public sealed class AwarenessClient
    {
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        private readonly string _baseUrl;

        public AwarenessClient(string baseUrl = "https://dynamicfeed.ai")
            => _baseUrl = baseUrl.TrimEnd('/');

        /// <summary>
        /// Fetches raw JSON for inspection only. The returned object has not been verified and
        /// carries no trust or lifecycle verdict.
        /// </summary>
        public async Task<JsonElement> FetchUnverifiedAwarenessAsync(
            string robotClass, double lat, double lon, double? altM = null,
            CancellationToken ct = default)
        {
            object location = altM is null
                ? new { lat, lon }
                : new { lat, lon, alt_m = altM };
            var payload = new { robot = new { @class = robotClass }, location };
            var json = JsonSerializer.Serialize(payload);

            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var resp = await Http.PostAsync($"{_baseUrl}/v1/awareness", content, ct);
            resp.EnsureSuccessStatusCode();
            var text = await resp.Content.ReadAsStringAsync();
            return JsonDocument.Parse(text).RootElement.Clone();
        }

        [Obsolete("Quarantined: no lifecycle-aware C# verifier exists. Use FetchUnverifiedAwarenessAsync only for inspection.")]
        public Task<JsonElement> AwarenessAsync(
            string robotClass, double lat, double lon, double? altM = null,
            CancellationToken ct = default)
            => throw new NotSupportedException(
                "C# policy verification is quarantined; use a conformance-tested Python, JavaScript, or Rust verifier.");

        [Obsolete("Quarantined: an unverified network verdict must never authorize an action.")]
        public Task<string> VerdictAsync(
            string robotClass, double lat, double lon, CancellationToken ct = default)
            => throw new NotSupportedException(
                "C# verdict extraction is disabled until lifecycle-aware verification is implemented and tested.");
    }
}
