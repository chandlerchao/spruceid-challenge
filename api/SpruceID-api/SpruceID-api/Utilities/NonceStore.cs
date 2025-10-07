using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace SpruceID_api.Utilities
{

    public class NonceStore : INonceStore
    {
        private readonly string _filePath;
        private readonly HashSet<string> _usedNonces = new HashSet<string>();
        private readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim();

        public NonceStore(string filePath)
        {
            _filePath = filePath;
            LoadNonces();
        }

        private void LoadNonces()
        {
            if (!File.Exists(_filePath))
                return;

            _lock.EnterWriteLock();
            try
            {
                foreach (var line in File.ReadAllLines(_filePath))
                {
                    var nonce = line.Trim();
                    if (!string.IsNullOrEmpty(nonce))
                    {
                        _usedNonces.Add(nonce);
                    }
                }
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        public bool IsNonceUsed(string nonce)
        {
            _lock.EnterReadLock();
            try
            {
                return _usedNonces.Contains(nonce);
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        public bool AddNonce(string nonce)
        {
            _lock.EnterWriteLock();
            try
            {
                if (_usedNonces.Contains(nonce))
                {
                    return false; // Nonce already used (replay)
                }

                File.AppendAllLines(_filePath, new[] { nonce });
                _usedNonces.Add(nonce);
                return true; // New nonce added
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        // Checks if nonce is new and adds it if so; returns false if replay
        public bool CheckAndAddNonce(string nonce)
        {
            _lock.EnterWriteLock();
            try
            {
                if (_usedNonces.Contains(nonce))
                {
                    return false; // Replay detected
                }

                File.AppendAllLines(_filePath, new[] { nonce });
                _usedNonces.Add(nonce);
                return true;
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }
    }
}