using Newtonsoft.Json;

namespace Server
{
    [JsonObject(MemberSerialization.OptOut)]
    public class SocketMessageFormat : IDisposable
    {
        public enum SocketMessageFlag
        {
            Enter = 0,
            Username = 1,
            Message = 2,
            UpdateUsersCollection = 3
        }

        private bool Disposed;

        [JsonProperty(PropertyName = "Flag")]
        public SocketMessageFlag Flag { get; set; }

        [JsonProperty(PropertyName = "Receiver")]
        public string Receiver { get; set; }

        [JsonProperty(PropertyName = "ForeignUser")]
        public string ForeignUser { get; set; }

        [JsonProperty(PropertyName = "Sender")]
        public string Sender { get; set; }

        [JsonProperty(PropertyName = "EncryptedMessage")]
        public byte[] EncryptedMessage { get; set; }

        [JsonProperty(PropertyName = "EncryptyedAesKey")]
        public byte[] EncryptyedAesKey { get; set; }

        [JsonProperty(PropertyName = "AesInitializationVector")]
        public byte[] AesInitializationVector { get; set; }

        [JsonProperty(PropertyName = "RsaPublicKey")]
        public byte[] RsaPublicKey { get; set; }

        protected virtual void Dispose(bool disposing)
        {
            if (!Disposed)
            {
                if (disposing)
                {
                    // TODO: eliminare lo stato gestito (oggetti gestiti)
                }

                Disposed = true;
            }
        }

        ~SocketMessageFormat()
        {
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
