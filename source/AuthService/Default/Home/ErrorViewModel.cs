using IdentityServer4.Models;

namespace AuthService
{
    public class ErrorViewModel
    {
        public ErrorViewModel(ErrorMessage errorMessage)
        {
            ErrorMessage = errorMessage;
        }

        public ErrorMessage ErrorMessage { get; set; }
    }
}
