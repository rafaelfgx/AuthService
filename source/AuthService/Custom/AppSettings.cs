namespace AuthService
{
    public sealed class AppSettings
    {
        public ConnectionStrings ConnectionStrings { get; set; }

        public Certificate Certificate { get; set; }

        public Azure Azure { get; set; }

        public Google Google { get; set; }
    }

    public sealed class ConnectionStrings
    {
        public string Database { get; set; }
    }

    public sealed class Certificate
    {
        public string Path { get; set; }

        public string Password { get; set; }
    }

    public sealed class Azure
    {
        public string Authority { get; set; }

        public string Issuer { get; set; }

        public string Audience { get; set; }

        public string ClientId { get; set; }
    }

    public sealed class Google
    {
        public string ClientId { get; set; }

        public string ClientSecret { get; set; }
    }
}
