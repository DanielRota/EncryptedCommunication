using System.Net.Sockets;
using Newtonsoft.Json;

namespace Server
{
    [JsonObject(MemberSerialization.OptOut)]
    public class MessageFormat : IDisposable
    {
        public enum PackageType
        {
            Username = 0,
            Message = 1,
            Update = 2,
            Join = 3
        }

        private bool Disposed;

        [JsonProperty(PropertyName = "Flag")]
        public PackageType Flag { get; set; }

        [JsonProperty(PropertyName = "Receiver")]
        public string Receiver { get; set; } = string.Empty;

        [JsonProperty(PropertyName = "Sender")]
        public string Sender { get; set; } = string.Empty;

        [JsonProperty(PropertyName = "RsaPublicKey")]
        public byte[] RsaPublicKey { get; set; }

        [JsonProperty(PropertyName = "EncryptedMessage")]
        public byte[] EncryptedMessage { get; set; }

        [JsonProperty(PropertyName = "EncryptyedAesKey")]
        public byte[] EncryptyedAesKey { get; set; }

        [JsonProperty(PropertyName = "AesInitializationVector")]
        public byte[] AesInitializationVector { get; set; }

        [JsonProperty(PropertyName = "UserKeys")]
        public List<UserKey> UserKeys { get; set; }

        protected virtual void Dispose(bool disposing)
        {
            if (!Disposed)
            {
                if (disposing)
                {

                }

                Disposed = true;
            }
        }

        ~MessageFormat()
        {
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    public sealed class UserKey
    {
        [JsonProperty(PropertyName = "User")]
        public string User { get; set; } = string.Empty;

        [JsonProperty(PropertyName = "Key")]
        public byte[] Key { get; set; }
    }

    public sealed class UserSocket
    {
        [JsonProperty(PropertyName = "User")]
        public string User { get; set; } = string.Empty;

        [JsonProperty(PropertyName = "Socket")]
        public Socket Socket { get; set; }
    }
}
