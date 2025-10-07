using NSec.Cryptography;
using SpruceID_api.Models;
using System.Text;

namespace SpruceID_api.Services
{
    public class SignatureVerificationService : ISignatureVerificationService
    {
        private readonly INonceStore _nonceStore;

        public SignatureVerificationService(INonceStore nonceStore)
        {
            _nonceStore = nonceStore;
        }

        public PublicKey LoadEd25519PublicKey(string publicKey)
        {
            // Remove PEM header/footer and decode base64
            var pemLines = publicKey.Split('\n');
            var base64 = string.Join("", pemLines
                .Where(line => !line.StartsWith("-----"))
                .Select(line => line.Trim()));
            byte[] keyBytes = Convert.FromBase64String(base64);

            // Ed25519 public key should be 32 bytes
            if (keyBytes.Length != 32)
                throw new ArgumentException("Invalid Ed25519 public key length.");

            // Load public key using NSec
            return PublicKey.Import(SignatureAlgorithm.Ed25519, keyBytes, KeyBlobFormat.RawPublicKey);
        }

        public bool CheckNonce(PayloadData payloadData)
        {
            if (_nonceStore.IsNonceUsed(payloadData.Nonce))
            {
                return false;
            }

            // Check if timestamp is within the last 5 minutes (300 seconds)
            var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (Math.Abs(currentTime - payloadData.Timestamp) > 300)
            {
                return false;
            }
            _nonceStore.AddNonce(payloadData.Nonce);
            return true;
        }

        public bool VerifySignature(PublicKey publicKey, string jsonPayload, string base64Signature)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(jsonPayload);
            byte[] signatureBytes = Convert.FromBase64String(base64Signature);

            // Use NSec.Cryptography for Ed25519 signature verification
            return SignatureAlgorithm.Ed25519.Verify(publicKey, dataBytes, signatureBytes);
        }
    }
}