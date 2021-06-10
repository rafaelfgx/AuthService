using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace AuthService
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IClientStore _clientStore;
        private readonly IEventService _eventService;
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        public AccountController
        (
            IClientStore clientStore,
            IEventService eventService,
            IIdentityServerInteractionService interactionService,
            IAuthenticationSchemeProvider schemeProvider,
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager
        )
        {
            _clientStore = clientStore;
            _eventService = eventService;
            _interactionService = interactionService;
            _schemeProvider = schemeProvider;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            var context = await _interactionService.GetAuthorizationContextAsync(model.ReturnUrl);

            if (button != "login")
            {
                if (context == null)
                {
                    return Redirect("~/");
                }

                await _interactionService.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                return context.IsNativeClient() ? this.LoadingPage("Redirect", model.ReturnUrl) : Redirect(model.ReturnUrl);
            }

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, true);

                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Username);

                    await _eventService.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

                    AuthenticationProperties properties = null;

                    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                    {
                        properties = new AuthenticationProperties
                        {
                            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration),
                            IsPersistent = true
                        };
                    }

                    var issuer = new IdentityServerUser(user.Id)
                    {
                        DisplayName = user.UserName
                    };

                    await HttpContext.SignInAsync(issuer, properties);

                    if (context != null)
                    {
                        return context.IsNativeClient() ? this.LoadingPage("Redirect", model.ReturnUrl) : Redirect(model.ReturnUrl);
                    }

                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }

                    if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }

                    throw new Exception("InvalidReturnUrl");
                }

                await _eventService.RaiseAsync(new UserLoginFailureEvent(model.Username, "InvalidCredentials", clientId: context?.Client.ClientId));

                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            var vm = await BuildLoginViewModelAsync(model);

            return View(vm);
        }

        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                return await Logout(vm);
            }

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                HttpContext.Request.Cookies.Keys.ToList().ForEach(cookie => HttpContext.Response.Cookies.Delete(cookie));

                await HttpContext.SignOutAsync();

                await _eventService.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            if (!vm.TriggerExternalSignout)
            {
                return View("LoggedOut", vm);
            }

            var url = Url.Action("Logout", new { logoutId = vm.LogoutId });

            return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            var logout = await _interactionService.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated != true)
            {
                return vm;
            }

            var identityProvider = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;

            if (identityProvider == null || identityProvider == IdentityServerConstants.LocalIdentityProvider)
            {
                return vm;
            }

            var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(identityProvider);

            if (!providerSupportsSignout)
            {
                return vm;
            }

            vm.LogoutId ??= await _interactionService.CreateLogoutContextAsync();

            vm.ExternalAuthenticationScheme = identityProvider;

            return vm;
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interactionService.GetAuthorizationContextAsync(returnUrl);

            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServerConstants.LocalIdentityProvider;

                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context.LoginHint
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(scheme => scheme.DisplayName != null)
                .Select(scheme => new ExternalProvider
                {
                    DisplayName = scheme.DisplayName ?? scheme.Name,
                    AuthenticationScheme = scheme.Name
                })
                .ToList();

            if (context?.Client.ClientId == null)
            {
                return new LoginViewModel
                {
                    AllowRememberLogin = AccountOptions.AllowRememberLogin,
                    EnableLocalLogin = AccountOptions.AllowLocalLogin,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                    ExternalProviders = providers.ToArray()
                };
            }

            var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);

            if (client == null)
            {
                return new LoginViewModel
                {
                    AllowRememberLogin = AccountOptions.AllowRememberLogin,
                    EnableLocalLogin = AccountOptions.AllowLocalLogin,
                    ReturnUrl = returnUrl,
                    Username = context.LoginHint,
                    ExternalProviders = providers.ToArray()
                };
            }

            var allowLocal = client.EnableLocalLogin;

            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
            {
                providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);

            vm.Username = model.Username;

            vm.RememberLogin = model.RememberLogin;

            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                vm.ShowLogoutPrompt = false;

                return vm;
            }

            var context = await _interactionService.GetLogoutContextAsync(logoutId);

            if (context?.ShowSignoutPrompt != false)
            {
                return vm;
            }

            vm.ShowLogoutPrompt = false;

            return vm;
        }
    }
}
