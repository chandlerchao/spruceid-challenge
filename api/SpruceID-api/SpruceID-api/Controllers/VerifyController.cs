using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

using SpruceID_api.Models;
using SpruceID_api.Services;

namespace SpruceID_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class VerifyController : ControllerBase
    {
        private const string PublicKeyFilePath = "Keys/public_raw.pem";
        private readonly ISignatureVerificationService _verificationService;

        public VerifyController(ISignatureVerificationService verificationService)
        {
            _verificationService = verificationService;
        }

        // POST api/verify
        [HttpPost]
        public IActionResult Post([FromBody] PayloadWithSignature request)
        {
            try
            {
                string publicKey = System.IO.File.ReadAllText(PublicKeyFilePath);
                var pk = _verificationService.LoadEd25519PublicKey(publicKey);

                if (pk == null)
                {
                    return BadRequest(new { message = "Invalid public key." });
                }

                if (request == null || request.Payload == null || string.IsNullOrEmpty(request.Signature))
                {
                    return BadRequest(new { message = "Payload and signature are required." });
                }

                // Deserialize Payload to PayloadData instance
                var payload = request.Payload.ToString();

                if (string.IsNullOrEmpty(payload))
                {
                    return BadRequest(new { message = "Payload is empty." });
                }

                var payloadData = JsonConvert.DeserializeObject<PayloadData>(payload);

                if (payloadData == null || string.IsNullOrEmpty(payloadData.Nonce) || payloadData.Timestamp == 0)
                {
                    return BadRequest(new { message = "Invalid payload structure." });
                }

                // Check nonce and timestamp
                if (!_verificationService.CheckNonce(payloadData))
                {
                    return Unauthorized(new { message = "Nonce has already been used or timestamp is invalid." });
                }

                // Verify signature
                bool verified = _verificationService.VerifySignature(pk, payload, request.Signature);

                if (verified)
                {
                    return Ok(new { message = "Signature is valid. Sender is authenticated." });
                }
                else
                {
                    return Unauthorized(new { message = "Invalid signature." });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }
    }
}
