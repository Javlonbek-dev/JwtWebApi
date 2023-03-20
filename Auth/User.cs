namespace Auth
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public byte[] Passwordhash { get; set; }
        public byte[] PaswwordSalt { get; set; }
    }
}
