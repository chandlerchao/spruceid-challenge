namespace SpruceID_api.Models
{
    public class PayloadData
    {
        public required string Message { get; set; }
        public required string Nonce { get; set; } 
        public required long Timestamp { get; set; }
    }
}
