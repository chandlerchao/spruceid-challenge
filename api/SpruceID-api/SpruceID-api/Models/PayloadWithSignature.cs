namespace SpruceID_api.Models
{
    public class PayloadWithSignature
    {
        public required object Payload { get; set; }

        public required string Signature { get; set; }
    }
}
