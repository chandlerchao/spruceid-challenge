using Moq;
using NSec.Cryptography;
using SpruceID_api.Models;
using SpruceID_api.Services;
using SpruceID_api.Utilities;

namespace SpruceIDapiTestProject.Services
{
    public class SignatureVerificationServiceTests
    {
        private readonly Mock<INonceStore> _nonceStoreMock;
        private readonly ISignatureVerificationService _service;

        public SignatureVerificationServiceTests()
        {
            _nonceStoreMock = new Mock<INonceStore>();
            _service = new SignatureVerificationService(_nonceStoreMock.Object);
        }

        [Fact]
        public void LoadEd25519PublicKey_ValidKey_ReturnsPublicKey()
        {
            // Arrange
            // Generate a valid Ed25519 public key (32 bytes)
            var algorithm = SignatureAlgorithm.Ed25519;
            using var key = Key.Create(algorithm);
            var publicKeyBytes = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            var base64 = Convert.ToBase64String(publicKeyBytes);
            var pem = $"-----BEGIN PUBLIC KEY-----\n{base64}\n-----END PUBLIC KEY-----";
            var service = new SignatureVerificationService(null);

            // Act
            var publicKey = service.LoadEd25519PublicKey(pem);

            // Assert
            Assert.NotNull(publicKey);
            Assert.Equal(publicKeyBytes, publicKey.Export(KeyBlobFormat.RawPublicKey));
        }

        [Fact]
        public void LoadEd25519PublicKey_InvalidLength_ThrowsArgumentException()
        {
            // Arrange
            var invalidBytes = new byte[16]; // Invalid length
            var base64 = Convert.ToBase64String(invalidBytes);
            var pem = $"-----BEGIN PUBLIC KEY-----\n{base64}\n-----END PUBLIC KEY-----";
            var service = new SignatureVerificationService(null);

            // Act & Assert
            Assert.Throws<ArgumentException>(() => service.LoadEd25519PublicKey(pem));
        }

        [Fact]
        public void LoadEd25519PublicKey_InvalidBase64_ThrowsFormatException()
        {
            // Arrange
            var pem = $"-----BEGIN PUBLIC KEY-----\nNotBase64!!\n-----END PUBLIC KEY-----";
            var service = new SignatureVerificationService(null);

            // Act & Assert
            Assert.Throws<FormatException>(() => service.LoadEd25519PublicKey(pem));
        }

        [Fact]
        public void CheckNonce_NonceAlreadyUsed_ReturnsFalse()
        {
            // Arrange
            var payload = new PayloadData
            {
                Nonce = "used-nonce",
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Message = "test"
            };
            _nonceStoreMock.Setup(x => x.IsNonceUsed("used-nonce")).Returns(true);

            // Act
            var result = _service.CheckNonce(payload);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void CheckNonce_TimestampOutOfRange_ReturnsFalse()
        {
            // Arrange
            var payload = new PayloadData
            {
                Nonce = "new-nonce",
                Timestamp = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds(),
                Message = "test"
            };
            _nonceStoreMock.Setup(x => x.IsNonceUsed("new-nonce")).Returns(false);

            // Act
            var result = _service.CheckNonce(payload);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void CheckNonce_ValidNonceAndTimestamp_ReturnsTrue()
        {
            // Arrange
            var payload = new PayloadData
            {
                Nonce = "valid-nonce",
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Message = "test"
            };
            _nonceStoreMock.Setup(x => x.IsNonceUsed("valid-nonce")).Returns(false);
            _nonceStoreMock.Setup(x => x.AddNonce("valid-nonce")).Returns(true);

            // Act
            var result = _service.CheckNonce(payload);

            // Assert
            Assert.True(result);
            _nonceStoreMock.Verify(x => x.AddNonce("valid-nonce"), Times.Once);
        }

        [Fact]
        public void VerifySignature_ValidSignature_ReturnsTrue()
        {
            // Arrange
            var nonceStore = new NonceStore("test_nonces.txt");
            var service = new SignatureVerificationService(nonceStore);

            // Generate Ed25519 key pair
            using var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var publicKey = key.PublicKey;

            string payload = "{\"test\":\"data\"}";
            byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(payload);
            byte[] signatureBytes = SignatureAlgorithm.Ed25519.Sign(key, dataBytes);
            string base64Signature = Convert.ToBase64String(signatureBytes);

            // Act
            bool result = service.VerifySignature(publicKey, payload, base64Signature);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifySignature_InvalidSignature_ReturnsFalse()
        {
            // Arrange
            var nonceStore = new NonceStore("test_nonces.txt");
            var service = new SignatureVerificationService(nonceStore);

            using var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var publicKey = key.PublicKey;

            string payload = "{\"test\":\"data\"}";
            byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(payload);
            byte[] signatureBytes = SignatureAlgorithm.Ed25519.Sign(key, dataBytes);

            // Tamper with signature
            signatureBytes[0] ^= 0xFF;
            string base64Signature = Convert.ToBase64String(signatureBytes);

            // Act
            bool result = service.VerifySignature(publicKey, payload, base64Signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifySignature_InvalidBase64Signature_ThrowsFormatException()
        {
            // Arrange
            var nonceStore = new NonceStore("test_nonces.txt");
            var service = new SignatureVerificationService(nonceStore);

            using var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var publicKey = key.PublicKey;

            string payload = "{\"test\":\"data\"}";
            string invalidBase64Signature = "!!!notbase64!!!";

            // Act & Assert
            Assert.Throws<FormatException>(() =>
                service.VerifySignature(publicKey, payload, invalidBase64Signature)
            );
        }
    }
}