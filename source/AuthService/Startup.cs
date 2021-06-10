using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService
{
    public class Startup
    {
        public void Configure(IApplicationBuilder application)
        {
            application.UseException();
            application.UseHsts();
            application.UseHttpsRedirection();
            application.UseCookiePolicy();
            application.UseCorsAllowAny();
            application.UseStaticFiles();
            application.UseRouting();
            application.UseIdentityServer();
            application.UseAuthentication();
            application.UseAuthorization();
            application.UseEndpoints();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAppSettings();
            services.AddCors();
            services.AddControllersWithViews();
            services.ConfigureIdentityServer();
        }
    }
}
