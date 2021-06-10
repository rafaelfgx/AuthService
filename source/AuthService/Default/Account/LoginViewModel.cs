using System.Collections.Generic;
using System.Linq;

namespace AuthService
{
    public class LoginViewModel : LoginInputModel
    {
        public bool AllowRememberLogin { get; set; } = true;

        public bool EnableLocalLogin { get; set; } = true;

        public string ExternalLoginScheme => IsExternalLoginOnly ? ExternalProviders?.SingleOrDefault()?.AuthenticationScheme : null;

        public IEnumerable<ExternalProvider> ExternalProviders { get; set; } = Enumerable.Empty<ExternalProvider>();

        public bool IsExternalLoginOnly => EnableLocalLogin == false && ExternalProviders?.Count() == 1;

        public IEnumerable<ExternalProvider> VisibleExternalProviders => ExternalProviders.Where(provider => !string.IsNullOrWhiteSpace(provider.DisplayName));
    }
}
