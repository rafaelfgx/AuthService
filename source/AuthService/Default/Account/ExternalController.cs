using IdentityModel;
using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthService
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class ExternalController : Controller
    {
        private readonly IEventService _eventService;
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly UserManager<IdentityUser> _userManager;

        public ExternalController
        (
            IEventService eventService,
            IIdentityServerInteractionService interactionService,
            UserManager<IdentityUser> userManager
        )
        {
            _eventService = eventService;
            _interactionService = interactionService;
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> Callback()
        {
            var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }

            var (user, provider, userId, claims) = await FindUserFromExternalProviderAsync(result);

            user ??= await AutoProvisionUserAsync(provider, userId, claims);

            var additionalClaims = new List<Claim>();

            var properties = new AuthenticationProperties();

            ProcessLoginCallback(result, additionalClaims, properties);

            var issuer = new IdentityServerUser(user.Id)
            {
                DisplayName = user.UserName,
                IdentityProvider = provider,
                AdditionalClaims = additionalClaims
            };

            await HttpContext.SignInAsync(issuer, properties);

            await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

            var context = await _interactionService.GetAuthorizationContextAsync(returnUrl);

            await _eventService.RaiseAsync(new UserLoginSuccessEvent(provider, userId, user.Id, user.UserName, true, context?.Client.ClientId));

            if (context == null)
            {
                return Redirect(returnUrl);
            }

            return context.IsNativeClient() ? this.LoadingPage("Redirect", returnUrl) : Redirect(returnUrl);
        }

        [HttpGet]
        public IActionResult Challenge(string scheme, string returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl))
            {
                returnUrl = "~/";
            }

            if (Url.IsLocalUrl(returnUrl) == false && _interactionService.IsValidReturnUrl(returnUrl) == false)
            {
                throw new Exception("InvalidReturnUrl");
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(Callback)),
                Items =
                {
                    { "returnUrl", returnUrl },
                    { "scheme", scheme }
                }
            };

            return Challenge(properties, scheme);
        }

        private static void ProcessLoginCallback(AuthenticateResult externalResult, ICollection<Claim> claims, AuthenticationProperties properties)
        {
            var sessionId = externalResult.Principal.Claims.FirstOrDefault(claim => claim.Type == JwtClaimTypes.SessionId);

            if (sessionId != null)
            {
                claims.Add(new Claim(JwtClaimTypes.SessionId, sessionId.Value));
            }

            var idToken = externalResult.Properties.GetTokenValue("id_token");

            if (idToken != null)
            {
                properties.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
            }
        }

        private async Task<IdentityUser> AutoProvisionUserAsync(string provider, string userId, IEnumerable<Claim> claims)
        {
            var filtered = new List<Claim>();

            var name = claims.FirstOrDefault(claim => claim.Type == JwtClaimTypes.Name)?.Value ?? claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Name)?.Value;

            if (name != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, name));
            }
            else
            {
                var givenName = claims.FirstOrDefault(claim => claim.Type == JwtClaimTypes.GivenName)?.Value ?? claims.FirstOrDefault(claim => claim.Type == ClaimTypes.GivenName)?.Value;

                var familyName = claims.FirstOrDefault(claim => claim.Type == JwtClaimTypes.FamilyName)?.Value ?? claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Surname)?.Value;

                if (givenName != null && familyName != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, givenName + " " + familyName));
                }
                else if (givenName != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, givenName));
                }
                else if (familyName != null)
                {
                    filtered.Add(new Claim(JwtClaimTypes.Name, familyName));
                }
            }

            var email = claims.FirstOrDefault(claim => claim.Type == JwtClaimTypes.Email)?.Value ?? claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Email)?.Value;

            if (email != null)
            {
                filtered.Add(new Claim(JwtClaimTypes.Email, email));
            }

            var user = new IdentityUser
            {
                UserName = Guid.NewGuid().ToString()
            };

            var identityResult = await _userManager.CreateAsync(user);

            if (!identityResult.Succeeded)
            {
                throw new Exception(identityResult.Errors.First().Description);
            }

            if (filtered.Any())
            {
                identityResult = await _userManager.AddClaimsAsync(user, filtered);

                if (!identityResult.Succeeded)
                {
                    throw new Exception(identityResult.Errors.First().Description);
                }
            }

            identityResult = await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, userId, provider));

            if (!identityResult.Succeeded)
            {
                throw new Exception(identityResult.Errors.First().Description);
            }

            return user;
        }

        private async Task<(IdentityUser user, string provider, string userId, IEnumerable<Claim> claims)> FindUserFromExternalProviderAsync(AuthenticateResult result)
        {
            var id =
                result.Principal.FindFirst(JwtClaimTypes.Subject) ??
                result.Principal.FindFirst(ClaimTypes.NameIdentifier) ??
                throw new Exception("UnknownUserId");

            var claims = result.Principal.Claims.ToList();

            claims.Remove(id);

            var provider = result.Properties.Items["scheme"];

            var user = await _userManager.FindByLoginAsync(provider, id.Value);

            return (user, provider, id.Value, claims);
        }
    }
}
