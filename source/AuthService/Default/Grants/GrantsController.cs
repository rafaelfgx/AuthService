using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthService
{
    [SecurityHeaders]
    [Authorize]
    public class GrantsController : Controller
    {
        private readonly IClientStore _clientStore;
        private readonly IEventService _eventService;
        private readonly IIdentityServerInteractionService _interactionService;
        private readonly IResourceStore _resourceStore;

        public GrantsController
        (
            IClientStore clientStore,
            IEventService eventService,
            IIdentityServerInteractionService interactionService,
            IResourceStore resourceStore
        )
        {
            _clientStore = clientStore;
            _eventService = eventService;
            _interactionService = interactionService;
            _resourceStore = resourceStore;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View(nameof(Index), await BuildViewModelAsync());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Revoke(string clientId)
        {
            await _interactionService.RevokeUserConsentAsync(clientId);

            await _eventService.RaiseAsync(new GrantsRevokedEvent(User.GetSubjectId(), clientId));

            return RedirectToAction(nameof(Index));
        }

        private async Task<GrantsViewModel> BuildViewModelAsync()
        {
            var userGrants = await _interactionService.GetAllUserGrantsAsync();

            var grants = new List<GrantViewModel>();

            foreach (var userGrant in userGrants)
            {
                var client = await _clientStore.FindClientByIdAsync(userGrant.ClientId);

                if (client == null)
                {
                    continue;
                }

                var resources = await _resourceStore.FindResourcesByScopeAsync(userGrant.Scopes);

                var grant = new GrantViewModel
                {
                    ApiGrantNames = resources.ApiScopes.Select(scope => scope.DisplayName ?? scope.Name).ToArray(),
                    ClientId = client.ClientId,
                    ClientLogoUrl = client.LogoUri,
                    ClientName = client.ClientName ?? client.ClientId,
                    ClientUrl = client.ClientUri,
                    Created = userGrant.CreationTime,
                    Description = userGrant.Description,
                    Expires = userGrant.Expiration,
                    IdentityGrantNames = resources.IdentityResources.Select(resource => resource.DisplayName ?? resource.Name).ToArray()
                };

                grants.Add(grant);
            }

            return new GrantsViewModel { Grants = grants };
        }
    }
}
