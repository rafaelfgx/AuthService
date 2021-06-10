using IdentityServer4.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using System.Threading.Tasks;

namespace AuthService
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class HomeController : Controller
    {
        private readonly IWebHostEnvironment _environment;
        private readonly IIdentityServerInteractionService _interactionService;

        public HomeController
        (
            IWebHostEnvironment environment,
            IIdentityServerInteractionService interactionService
        )
        {
            _environment = environment;
            _interactionService = interactionService;
        }

        public async Task<IActionResult> Error(string errorId)
        {
            var errorMessage = await _interactionService.GetErrorContextAsync(errorId);

            if (errorMessage == null || !_environment.IsDevelopment())
            {
                return View(nameof(Error));
            }

            return View(nameof(Error), new ErrorViewModel(errorMessage));
        }

        public IActionResult Index()
        {
            return View();
        }
    }
}
