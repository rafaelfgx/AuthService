using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthService
{
    [Authorize]
    [SecurityHeaders]
    public class DeviceController : Controller
    {
        private readonly IEventService _eventService;
        private readonly IDeviceFlowInteractionService _interactionService;
        private readonly IOptions<IdentityServerOptions> _options;

        public DeviceController
        (
            IEventService eventService,
            IDeviceFlowInteractionService interactionService,
            IOptions<IdentityServerOptions> options
        )
        {
            _eventService = eventService;
            _interactionService = interactionService;
            _options = options;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Callback(DeviceAuthorizationInputModel model)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            var result = await ProcessConsent(model);

            return View(result.HasValidationError ? "Error" : "Success");
        }

        public ScopeViewModel CreateScopeViewModel(ParsedScopeValue parsedScopeValue, ApiScope apiScope, bool check)
        {
            return new ScopeViewModel
            {
                Checked = check || apiScope.Required,
                Description = apiScope.Description,
                DisplayName = apiScope.DisplayName ?? apiScope.Name,
                Emphasize = apiScope.Emphasize,
                Required = apiScope.Required,
                Value = parsedScopeValue.RawValue
            };
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var userCode = Request.Query[_options.Value.UserInteraction.DeviceVerificationUserCodeParameter];

            if (string.IsNullOrWhiteSpace(userCode))
            {
                return View("UserCodeCapture");
            }

            var vm = await BuildViewModelAsync(userCode);

            if (vm == null)
            {
                return View("Error");
            }

            vm.ConfirmUserCode = true;

            return View("UserCodeConfirmation", vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UserCodeCapture(string userCode)
        {
            var vm = await BuildViewModelAsync(userCode);

            return vm == null ? View("Error") : View("UserCodeConfirmation", vm);
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

        private async Task<DeviceAuthorizationViewModel> BuildViewModelAsync(string userCode, DeviceAuthorizationInputModel model = null)
        {
            var request = await _interactionService.GetAuthorizationContextAsync(userCode);

            return request != null ? CreateConsentViewModel(userCode, model, request) : null;
        }

        private DeviceAuthorizationViewModel CreateConsentViewModel(string userCode, DeviceAuthorizationInputModel model, DeviceFlowAuthorizationRequest request)
        {
            var vm = new DeviceAuthorizationViewModel
            {
                AllowRememberConsent = request.Client.AllowRememberConsent,
                ClientLogoUrl = request.Client.LogoUri,
                ClientName = request.Client.ClientName ?? request.Client.ClientId,
                ClientUrl = request.Client.ClientUri,
                Description = model?.Description,
                RememberConsent = model?.RememberConsent ?? true,
                ScopesConsented = model?.ScopesConsented ?? Enumerable.Empty<string>(),
                UserCode = userCode
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

        private async Task<ProcessConsentResult> ProcessConsent(DeviceAuthorizationInputModel model)
        {
            var result = new ProcessConsentResult();

            var request = await _interactionService.GetAuthorizationContextAsync(model.UserCode);

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
                await _interactionService.HandleRequestAsync(model.UserCode, consentResponse);

                result.Client = request.Client;

                result.RedirectUri = model.ReturnUrl;
            }
            else
            {
                result.ViewModel = await BuildViewModelAsync(model.UserCode, model);
            }

            return result;
        }
    }
}
