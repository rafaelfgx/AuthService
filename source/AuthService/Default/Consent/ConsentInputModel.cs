using System.Collections.Generic;

namespace AuthService
{
    public class ConsentInputModel
    {
        public string Button { get; set; }

        public string Description { get; set; }

        public bool RememberConsent { get; set; }

        public string ReturnUrl { get; set; }

        public IEnumerable<string> ScopesConsented { get; set; }
    }
}
