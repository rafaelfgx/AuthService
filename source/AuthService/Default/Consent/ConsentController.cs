using IdentityServer4;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthService
{
    [SecurityHeaders]
    [Authorize]
    public class ConsentController : Controller
    {
        private readonly IEventService _eventService;
        private readonly IIdentityServerInteractionService _interactionService;

        public ConsentController
        (
            IEventService eventService,
            IIdentityServerInteractionService interactionService
        )
        {
            _eventService = eventService;
            _interactionService = interactionService;
        }

        public ScopeViewModel CreateScopeViewModel(ParsedScopeValue parsedScopeValue, ApiScope apiScope, bool check)
        {
            var displayName = apiScope.DisplayName ?? apiScope.Name;

            if (!string.IsNullOrWhiteSpace(parsedScopeValue.ParsedParameter))
            {
                displayName += ":" + parsedScopeValue.ParsedParameter;
            }

            return new ScopeViewModel
            {
                Checked = check || apiScope.Required,
                Description = apiScope.Description,
                DisplayName = displayName,
                Emphasize = apiScope.Emphasize,
                Required = apiScope.Required,
                Value = parsedScopeValue.RawValue
            };
        }

        [HttpGet]
        public async Task<IActionResult> Index(string returnUrl)
        {
            var vm = await BuildViewModelAsync(returnUrl);

            return vm != null ? View("Index", vm) : View("Error");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(ConsentInputModel model)
        {
            var result = await ProcessConsent(model);

            if (result.IsRedirect)
            {
                var context = await _interactionService.GetAuthorizationContextAsync(model.ReturnUrl);

                return context?.IsNativeClient() == true ? this.LoadingPage("Redirect", result.RedirectUri) : Redirect(result.RedirectUri);
            }

            if (result.HasValidationError)
            {
                ModelState.AddModelError(string.Empty, result.ValidationError);
            }

            return result.ShowView ? View("Index", result.ViewModel) : View("Error");
        }

        private static ScopeViewModel CreateScopeViewModel(IdentityResource identity, bool check)
        {
            return new ScopeViewModel
            {
                Checked = check || identity.Required,
                Description = identity.Description,
                DisplayName = identity.DisplayName ?? identity.Name,
                Emphasize = identity.Emphasize,
                Required = identity.Required,
                Value = identity.Name
            };
        }

        private static ScopeViewModel GetOfflineAccessScope(bool check)
        {
            return new ScopeViewModel
            {
                Checked = check,
                Description = ConsentOptions.OfflineAccessDescription,
                DisplayName = ConsentOptions.OfflineAccessDisplayName,
                Emphasize = true,
                Value = IdentityServerConstants.StandardScopes.OfflineAccess
            };
        }

        private async Task<ConsentViewModel> BuildViewModelAsync(string returnUrl, ConsentInputModel model = null)
        {
            var request = await _interactionService.GetAuthorizationContextAsync(returnUrl);

            return request != null ? CreateConsentViewModel(model, returnUrl, request) : null;
        }

        private ConsentViewModel CreateConsentViewModel(ConsentInputModel model, string returnUrl, AuthorizationRequest request)
        {
            var vm = new ConsentViewModel
            {
                AllowRememberConsent = request.Client.AllowRememberConsent,
                ClientLogoUrl = request.Client.LogoUri,
                ClientName = request.Client.ClientName ?? request.Client.ClientId,
                ClientUrl = request.Client.ClientUri,
                Description = model?.Description,
                RememberConsent = model?.RememberConsent ?? true,
                ReturnUrl = returnUrl,
                ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>()
            };

            vm.IdentityScopes = request.ValidatedResources.Resources.IdentityResources.Select(resource => CreateScopeViewModel(resource, vm.ScopesConsented.Contains(resource.Name) || model == null)).ToArray();

            var apiScopes = new List<ScopeViewModel>();

            foreach (var parsedScope in request.ValidatedResources.ParsedScopes)
            {
                var apiScope = request.ValidatedResources.Resources.FindApiScope(parsedScope.ParsedName);

                if (apiScope == null)
                {
                    continue;
                }

                var scope = CreateScopeViewModel(parsedScope, apiScope, vm.ScopesConsented.Contains(parsedScope.RawValue) || model == null);

                apiScopes.Add(scope);
            }

            if (ConsentOptions.EnableOfflineAccess && request.ValidatedResources.Resources.OfflineAccess)
            {
                apiScopes.Add(GetOfflineAccessScope(vm.ScopesConsented.Contains(IdentityServerConstants.StandardScopes.OfflineAccess) || model == null));
            }

            vm.ApiScopes = apiScopes;

            return vm;
        }

        private async Task<ProcessConsentResult> ProcessConsent(ConsentInputModel model)
        {
            var result = new ProcessConsentResult();

            var request = await _interactionService.GetAuthorizationContextAsync(model.ReturnUrl);

            if (request == null)
            {
                return result;
            }

            ConsentResponse consentResponse = null;

            switch (model.Button)
            {
                case "no":
                    {
                        consentResponse = new ConsentResponse { Error = AuthorizationError.AccessDenied };

                        await _eventService.RaiseAsync(new ConsentDeniedEvent(User.GetSubjectId(), request.Client.ClientId, request.ValidatedResources.RawScopeValues));

                        break;
                    }
                case "yes" when model.ScopesConsented != null && model.ScopesConsented.Any():
                    {
                        var scopes = model.ScopesConsented;

                        if (ConsentOptions.EnableOfflineAccess == false)
                        {
                            scopes = scopes.Where(scope => scope != IdentityServerConstants.StandardScopes.OfflineAccess);
                        }

                        consentResponse = new ConsentResponse
                        {
                            Description = model.Description,
                            RememberConsent = model.RememberConsent,
                            ScopesValuesConsented = scopes.ToArray()
                        };

                        await _eventService.RaiseAsync(new ConsentGrantedEvent(User.GetSubjectId(), request.Client.ClientId, request.ValidatedResources.RawScopeValues, consentResponse.ScopesValuesConsented, consentResponse.RememberConsent));

                        break;
                    }
                case "yes":
                    {
                        result.ValidationError = ConsentOptions.MustChooseOneErrorMessage;

                        break;
                    }
                default:
                    {
                        result.ValidationError = ConsentOptions.InvalidSelectionErrorMessage;

                        break;
                    }
            }

            if (consentResponse != null)
            {
                await _interactionService.GrantConsentAsync(request, consentResponse);

                result.Client = request.Client;

                result.RedirectUri = model.ReturnUrl;
            }
            else
            {
                result.ViewModel = await BuildViewModelAsync(model.ReturnUrl, model);
            }

            return result;
        }
    }
}
