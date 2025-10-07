using System;
using System.IO;
using Xunit;
using SpruceID_api.Utilities;

namespace SpruceIDapiTestProject.Utilities
{
    public class NonceStoreTests : IDisposable
    {
        private readonly string _testFilePath;

        public NonceStoreTests()
        {
            _testFilePath = Path.GetTempFileName();
        }

        public void Dispose()
        {
            if (File.Exists(_testFilePath))
                File.Delete(_testFilePath);
        }

        [Fact]
        public void AddNonce_NewNonce_ReturnsTrueAndPersists()
        {
            var store = new NonceStore(_testFilePath);
            var nonce = Guid.NewGuid().ToString();

            var result = store.AddNonce(nonce);

            Assert.True(result);
            Assert.True(store.IsNonceUsed(nonce));
            Assert.Contains(nonce, File.ReadAllLines(_testFilePath));
        }

        [Fact]
        public void AddNonce_ExistingNonce_ReturnsFalse()
        {
            var store = new NonceStore(_testFilePath);
            var nonce = Guid.NewGuid().ToString();

            Assert.True(store.AddNonce(nonce));
            Assert.False(store.AddNonce(nonce));
        }

        [Fact]
        public void IsNonceUsed_NonceNotAdded_ReturnsFalse()
        {
            var store = new NonceStore(_testFilePath);
            var nonce = Guid.NewGuid().ToString();

            Assert.False(store.IsNonceUsed(nonce));
        }

        [Fact]
        public void CheckAndAddNonce_NewNonce_ReturnsTrueAndPersists()
        {
            var store = new NonceStore(_testFilePath);
            var nonce = Guid.NewGuid().ToString();

            var result = store.CheckAndAddNonce(nonce);

            Assert.True(result);
            Assert.True(store.IsNonceUsed(nonce));
        }

        [Fact]
        public void CheckAndAddNonce_ExistingNonce_ReturnsFalse()
        {
            var store = new NonceStore(_testFilePath);
            var nonce = Guid.NewGuid().ToString();

            Assert.True(store.CheckAndAddNonce(nonce));
            Assert.False(store.CheckAndAddNonce(nonce));
        }

        [Fact]
        public void NonceStore_LoadsNoncesFromFile()
        {
            var nonce = Guid.NewGuid().ToString();
            File.WriteAllLines(_testFilePath, new[] { nonce });

            var store = new NonceStore(_testFilePath);

            Assert.True(store.IsNonceUsed(nonce));
        }
    }
}