using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

using SpruceID_api.Models;
using SpruceID_api.Utilities;
using SpruceID_api.Services;

namespace SpruceID_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class VerifyController : ControllerBase
    {
        private const string PublicKeyFilePath = "Keys/id_ed25519.pub";
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

                if (!_verificationService.CheckNonce((PayloadData)request.Payload))
                {
                    return Unauthorized(new { message = "Nonce has already been used or timestamp is invalid." });
                }

                string jsonPayload = JsonConvert.SerializeObject(request.Payload);
                bool verified = _verificationService.VerifySignature(pk, jsonPayload, request.Signature);

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
