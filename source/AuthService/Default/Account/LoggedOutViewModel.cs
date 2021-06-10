namespace AuthService
{
    public class LoggedOutViewModel
    {
        public bool AutomaticRedirectAfterSignOut { get; set; }

        public string ClientName { get; set; }

        public string ExternalAuthenticationScheme { get; set; }

        public string LogoutId { get; set; }

        public string PostLogoutRedirectUri { get; set; }

        public string SignOutIframeUrl { get; set; }

        public bool TriggerExternalSignout => ExternalAuthenticationScheme != null;
    }
}
