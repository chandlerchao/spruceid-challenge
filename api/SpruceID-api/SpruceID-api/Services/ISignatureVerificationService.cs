using NSec.Cryptography;
using SpruceID_api.Models;

namespace SpruceID_api.Services
{
    public interface ISignatureVerificationService
    {
        PublicKey LoadEd25519PublicKey(string publicKey);
        bool CheckNonce(PayloadData payloadData);
        bool VerifySignature(PublicKey publicKey, string jsonPayload, string base64Signature);
    }
}