public interface INonceStore
{
    bool IsNonceUsed(string nonce);
    bool AddNonce(string nonce);
}