using System.Collections.Generic;

namespace AuthService
{
    public class ConsentViewModel : ConsentInputModel
    {
        public bool AllowRememberConsent { get; set; }

        public IEnumerable<ScopeViewModel> ApiScopes { get; set; }

        public string ClientLogoUrl { get; set; }

        public string ClientName { get; set; }

        public string ClientUrl { get; set; }

        public IEnumerable<ScopeViewModel> IdentityScopes { get; set; }
    }
}
