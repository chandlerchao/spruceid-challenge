using Xunit;
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
        private readonly Mock<ISignatureVerificationService> _mockVerificationService;
        private readonly VerifyController _controller;

        public VerifyControllerTests()
        {
            _mockVerificationService = new Mock<ISignatureVerificationService>();
            // Use a derived controller that accepts the service for testing
            _controller = new TestableVerifyController(_mockVerificationService.Object);
        }

        [Fact]
        public void Post_ValidSignature_ReturnsOk()
        {
            var payload = new PayloadData { Message = "msg", Nonce = "nonce", Timestamp = 1234567890 };
            var request = new PayloadWithSignature { Payload = payload, Signature = "validsig" };
            var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);

            _mockVerificationService.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(publicKey);
            _mockVerificationService.Setup(s => s.CheckNonce(payload)).Returns(true);
            _mockVerificationService.Setup(s => s.VerifySignature(publicKey, It.IsAny<string>(), "validsig")).Returns(true);

            var result = _controller.Post(request);

            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Contains("Signature is valid", okResult.Value.ToString());
        }

        [Fact]
        public void Post_InvalidSignature_ReturnsUnauthorized()
        {
            var payload = new PayloadData { Message = "msg", Nonce = "nonce", Timestamp = 1234567890 };
            var request = new PayloadWithSignature { Payload = payload, Signature = "invalidsig" };
            var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);

            _mockVerificationService.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(publicKey);
            _mockVerificationService.Setup(s => s.CheckNonce(payload)).Returns(true);
            _mockVerificationService.Setup(s => s.VerifySignature(publicKey, It.IsAny<string>(), "invalidsig")).Returns(false);

            var result = _controller.Post(request);

            var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Contains("Invalid signature", unauthorizedResult.Value.ToString());
        }

        [Fact]
        public void Post_UsedNonce_ReturnsUnauthorized()
        {
            var payload = new PayloadData { Message = "msg", Nonce = "usednonce", Timestamp = 1234567890 };
            var request = new PayloadWithSignature { Payload = payload, Signature = "anysig" };
            var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, new byte[32], KeyBlobFormat.RawPublicKey);

            _mockVerificationService.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Returns(publicKey);
            _mockVerificationService.Setup(s => s.CheckNonce(payload)).Returns(false);

            var result = _controller.Post(request);

            var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Contains("Nonce has already been used", unauthorizedResult.Value.ToString());
        }

        [Fact]
        public void Post_ExceptionThrown_ReturnsBadRequest()
        {
            var payload = new PayloadData { Message = "msg", Nonce = "nonce", Timestamp = 1234567890 };
            var request = new PayloadWithSignature { Payload = payload, Signature = "anysig" };

            _mockVerificationService.Setup(s => s.LoadEd25519PublicKey(It.IsAny<string>())).Throws(new Exception("File not found"));

            var result = _controller.Post(request);

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Contains("File not found", badRequestResult.Value.ToString());
        }

        // Helper to inject the mock service
        private class TestableVerifyController : VerifyController
        {
            public TestableVerifyController(ISignatureVerificationService verificationService)
                : base(verificationService)
            {
                // No need for reflection; base constructor sets the field.
            }
        }
    }
}