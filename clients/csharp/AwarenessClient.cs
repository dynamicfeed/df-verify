// AwarenessClient.cs — reference C# client for the Dynamic Feed robot situational-awareness API.
// Target: .NET 6+. No external packages required for the call itself (System.Text.Json + HttpClient).
// Signature verification (optional) needs BouncyCastle — see the note at the bottom.
//
//   var df = new DynamicFeed.AwarenessClient();
//   string verdict = await df.VerdictAsync("aerial", 51.5, -0.12);   // "go" | "caution" | "no-go"
//   if (verdict != "go") AbortTakeoff();
//
// The server NEVER hangs (hard deadline; degrades to "caution"), and this client mirrors that
// fail-safe contract: any error returns "caution", never an exception into your control loop.

using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DynamicFeed
{
    public sealed class AwarenessClient
    {
        private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        private readonly string _baseUrl;

        public AwarenessClient(string baseUrl = "https://dynamicfeed.ai")
            => _baseUrl = baseUrl.TrimEnd('/');

        /// <summary>Full awareness snapshot (verdict + grounded facts + Ed25519 signature) as JSON.</summary>
        public async Task<JsonElement> AwarenessAsync(
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

        /// <summary>
        /// Returns "go" | "caution" | "no-go". Fail-safe: on ANY error (timeout, network, parse) it
        /// returns "caution" rather than throwing — safe to call from a real-time control loop.
        /// </summary>
        public async Task<string> VerdictAsync(
            string robotClass, double lat, double lon, CancellationToken ct = default)
        {
            try
            {
                var root = await AwarenessAsync(robotClass, lat, lon, null, ct);
                return root.GetProperty("verdict").GetProperty("status").GetString() ?? "caution";
            }
            catch
            {
                return "caution";
            }
        }
    }
}

// ── Signature verification (optional, recommended for tamper-evidence) ────────────────────────────
// Every response carries: "signature": { "alg":"Ed25519", "key_id":"...", "canonicalization":
// "json-sorted-compact", "sig":"<base64url>" }.
// To verify:
//   1. GET https://dynamicfeed.ai/.well-known/keys  →  { "<key_id>": "<base64url 32-byte raw public key>" }.
//   2. Re-serialize the response WITHOUT its "signature" field as canonical JSON
//      (UTF-8, keys sorted, separators "," and ":").
//   3. Verify with BouncyCastle:
//        var verifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
//        verifier.Init(false, new Ed25519PublicKeyParameters(rawPublicKeyBytes, 0));
//        verifier.BlockUpdate(canonicalBytes, 0, canonicalBytes.Length);
//        bool ok = verifier.VerifySignature(signatureBytes);
//   If ok is false, the snapshot was altered — reject it.
