using IdentityServer4.Models;

namespace AuthService
{
    public class ProcessConsentResult
    {
        public Client Client { get; set; }

        public bool HasValidationError => ValidationError != null;

        public bool IsRedirect => RedirectUri != null;

        public string RedirectUri { get; set; }

        public bool ShowView => ViewModel != null;

        public string ValidationError { get; set; }

        public ConsentViewModel ViewModel { get; set; }
    }
}
