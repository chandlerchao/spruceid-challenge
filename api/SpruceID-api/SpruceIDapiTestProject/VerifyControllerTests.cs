using Moq;
using Microsoft.AspNetCore.Mvc;
using SpruceID_api.Controllers;
using SpruceID_api.Models;
using SpruceID_api.Services;
using NSec.Cryptography;

namespace SpruceIDapiTestProject.Controllers
{
    public class VerifyControllerTests
    {
        private readonly Mock<ISignatureVerificationService> _verificationServiceMock;
        private readonly VerifyController _controller;

        public VerifyControllerTests()
        {
            _verificationServiceMock = new Mock<ISignatureVerificationService>();
            _controller = new VerifyController(_verificationServiceMock.Object);
        }

        [Fact]
        public void Post_ReturnsBadRequest_WhenPublicKeyIsInvalid()
        {
            _verificationServiceMock.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns((PublicKey)null);

            var request = new PayloadWithSignature { Payload = new { }, Signature = "sig" };
            var result = _controller.Post(request);

            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Contains("Invalid public key", badRequest.Value.ToString());
        }

        [Fact]
        public void Post_ReturnsBadRequest_WhenPayloadOrSignatureIsMissing()
        {
            // Use a valid PublicKey instance via Import (since PublicKey has no public constructor)
            var pk = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);
            _verificationServiceMock.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(pk);

            var result = _controller.Post(null);

            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Contains("Payload and signature are required", badRequest.Value.ToString());
        }

        [Fact]
        public void Post_ReturnsBadRequest_WhenPayloadIsEmpty()
        {
            var pk = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);
            _verificationServiceMock.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(pk);

            var request = new PayloadWithSignature { Payload = "", Signature = "sig" };
            var result = _controller.Post(request);

            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Contains("Payload is empty", badRequest.Value.ToString());
        }

        [Fact]
        public void Post_ReturnsBadRequest_WhenPayloadStructureIsInvalid()
        {
            var pk = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);
            _verificationServiceMock.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(pk);

            var request = new PayloadWithSignature { Payload = "{}", Signature = "sig" };
            var result = _controller.Post(request);

            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Contains("Invalid payload structure", badRequest.Value.ToString());
        }

        [Fact]
        public void Post_ReturnsUnauthorized_WhenNonceCheckFails()
        {
            var pk = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);
            _verificationServiceMock.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(pk);
            _verificationServiceMock.Setup(s => s.CheckNonce(It.IsAny<PayloadData>())).Returns(false);

            var payloadData = new PayloadData { Message = "msg", Nonce = "nonce", Timestamp = 1234567890 };
            var payloadJson = Newtonsoft.Json.JsonConvert.SerializeObject(payloadData);
            var request = new PayloadWithSignature { Payload = payloadJson, Signature = "sig" };

            var result = _controller.Post(request);

            var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Contains("Nonce has already been used", unauthorized.Value.ToString());
        }

        [Fact]
        public void Post_ReturnsOk_WhenSignatureIsValid()
        {
            var pk = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);
            _verificationServiceMock.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(pk);
            _verificationServiceMock.Setup(s => s.CheckNonce(It.IsAny<PayloadData>())).Returns(true);
            _verificationServiceMock.Setup(s => s.VerifySignature(pk, It.IsAny<string>(), It.IsAny<string>())).Returns(true);

            var payloadData = new PayloadData { Message = "msg", Nonce = "nonce", Timestamp = 1234567890 };
            var payloadJson = Newtonsoft.Json.JsonConvert.SerializeObject(payloadData);
            var request = new PayloadWithSignature { Payload = payloadJson, Signature = "sig" };

            var result = _controller.Post(request);

            var ok = Assert.IsType<OkObjectResult>(result);
            Assert.Contains("Signature is valid", ok.Value.ToString());
        }

        [Fact]
        public void Post_ReturnsUnauthorized_WhenSignatureIsInvalid()
        {
            var pk = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);
            _verificationServiceMock.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(pk);
            _verificationServiceMock.Setup(s => s.CheckNonce(It.IsAny<PayloadData>())).Returns(true);
            _verificationServiceMock.Setup(s => s.VerifySignature(pk, It.IsAny<string>(), It.IsAny<string>())).Returns(false);

            var payloadData = new PayloadData { Message = "msg", Nonce = "nonce", Timestamp = 1234567890 };
            var payloadJson = Newtonsoft.Json.JsonConvert.SerializeObject(payloadData);
            var request = new PayloadWithSignature { Payload = payloadJson, Signature = "sig" };

            var result = _controller.Post(request);

            var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Contains("Invalid signature", unauthorized.Value.ToString());
        }
    }
}