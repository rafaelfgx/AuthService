using IdentityServer4;
using IdentityServer4.EntityFramework.DbContexts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace AuthService
{
    public static class Extensions
    {
        public static AppSettings AddAppSettings(this IServiceCollection services)
        {
            var appSettings = services.Configuration().Get<AppSettings>();

            services.AddSingleton(appSettings);

            return appSettings;
        }

        public static IServiceCollection AddCors(this IServiceCollection services)
        {
            return services.AddCors(options => options.AddPolicy("AllowAny", policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));
        }

        public static IServiceCollection ConfigureIdentityServer(this IServiceCollection services)
        {
            services
                .AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<IdentityDbContext>()
                .AddIdentityStore()
                .AddDefaultTokenProviders();

            services
                .AddIdentityServer()
                .AddConfigurationStore()
                .AddOperationalStore()
                .AddAspNetIdentity<IdentityUser>()
                .AddSigningCredential();

            services
                .AddLocalApiAuthentication()
                .AddAuthentication()
                .AddExternalAzure()
                .AddExternalGoogle()
                .AddCookie();

            return services;
        }

        public static void Connection(this DbContextOptionsBuilder builder)
        {
            builder.Connection("Data Source=Auth.db;");
        }

        public static IApplicationBuilder UseCorsAllowAny(this IApplicationBuilder application)
        {
            return application.UseCors("AllowAny");
        }

        public static IApplicationBuilder UseEndpoints(this IApplicationBuilder application)
        {
            return application.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
        }

        public static IApplicationBuilder UseException(this IApplicationBuilder application)
        {
            var environment = application.ApplicationServices.GetRequiredService<IWebHostEnvironment>();

            if (environment.IsDevelopment())
            {
                application.UseDeveloperExceptionPage();
            }

            return application;
        }

        private static IIdentityServerBuilder AddConfigurationStore(this IIdentityServerBuilder builder)
        {
            var appSettings = builder.Services.BuildServiceProvider().GetRequiredService<AppSettings>();

            builder.AddConfigurationStore(options => options.ConfigureDbContext = optionsBuilder => optionsBuilder.Connection(appSettings.ConnectionStrings.Database));

            var context = builder.Services.BuildServiceProvider().GetRequiredService<ConfigurationDbContext>();

            context.Database.Migrate();

            context.Seed();

            return builder;
        }

        private static void AddCookie(this AuthenticationBuilder builder)
        {
            builder.AddCookie(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            });

            builder.Services.AddAntiforgery(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            });

            builder.Services.Configure<CookiePolicyOptions>(options =>
            {
                options.HttpOnly = HttpOnlyPolicy.Always;
                options.MinimumSameSitePolicy = SameSiteMode.Lax;
                options.Secure = CookieSecurePolicy.SameAsRequest;
            });
        }

        private static AuthenticationBuilder AddExternalAzure(this AuthenticationBuilder builder)
        {
            var appSettings = builder.Services.BuildServiceProvider().GetRequiredService<AppSettings>();

            if (appSettings is null || appSettings.Azure is null || string.IsNullOrWhiteSpace(appSettings.Azure.ClientId))
            {
                return builder;
            }

            builder.AddOpenIdConnect("aad", "Azure", options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                options.CallbackPath = "/signin-aad";
                options.RemoteSignOutPath = "/signout-aad";
                options.ResponseType = "id_token";
                options.SignedOutCallbackPath = "/signout-callback-aad";
                options.Authority = appSettings.Azure.Authority;
                options.ClientId = appSettings.Azure.ClientId;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = !string.IsNullOrWhiteSpace(appSettings.Azure.Audience),
                    ValidateIssuer = !string.IsNullOrWhiteSpace(appSettings.Azure.Issuer),
                    ValidAudience = appSettings.Azure.Audience,
                    ValidIssuer = appSettings.Azure.Issuer,
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };
            });

            builder.Services.AddOidcStateDataFormatterCache("aad");

            return builder;
        }

        private static AuthenticationBuilder AddExternalGoogle(this AuthenticationBuilder builder)
        {
            var appSettings = builder.Services.BuildServiceProvider().GetRequiredService<AppSettings>();

            if (appSettings is null || appSettings.Google is null || string.IsNullOrWhiteSpace(appSettings.Google.ClientId))
            {
                return builder;
            }

            return builder.AddGoogle("Google", options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.ClientId = appSettings.Google.ClientId;
                options.ClientSecret = appSettings.Google.ClientSecret;
            });
        }

        private static IdentityBuilder AddIdentityStore(this IdentityBuilder builder)
        {
            var appSettings = builder.Services.BuildServiceProvider().GetRequiredService<AppSettings>();

            builder.Services.AddDbContextPool<IdentityDbContext>(options => options.Connection(appSettings.ConnectionStrings.Database));

            var provider = builder.Services.BuildServiceProvider();

            provider.GetRequiredService<IdentityDbContext>().Database.Migrate();

            provider.GetRequiredService<UserManager<IdentityUser>>().Seed();

            return builder;
        }

        private static IIdentityServerBuilder AddOperationalStore(this IIdentityServerBuilder builder)
        {
            var appSettings = builder.Services.BuildServiceProvider().GetRequiredService<AppSettings>();

            builder.AddOperationalStore(options => options.ConfigureDbContext = optionsBuilder => optionsBuilder.Connection(appSettings.ConnectionStrings.Database));

            builder.Services.BuildServiceProvider().GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

            return builder;
        }

        private static void AddSigningCredential(this IIdentityServerBuilder builder)
        {
            var environment = builder.Services.BuildServiceProvider().GetRequiredService<IWebHostEnvironment>();

            if (environment.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }
            else
            {
                var appSettings = builder.Services.BuildServiceProvider().GetRequiredService<AppSettings>();

                builder.AddSigningCredential(new X509Certificate2(appSettings.Certificate.Path, appSettings.Certificate.Password, X509KeyStorageFlags.Exportable));
            }
        }

        private static IConfigurationRoot Configuration(this IServiceCollection services)
        {
            var environment = services.BuildServiceProvider().GetRequiredService<IHostEnvironment>();

            return new ConfigurationBuilder()
                .SetBasePath(environment.ContentRootPath)
                .AddJsonFile("AppSettings.json", false, true)
                .AddJsonFile($"AppSettings.{environment.EnvironmentName}.json", true)
                .AddEnvironmentVariables()
                .Build();
        }

        private static void Connection(this DbContextOptionsBuilder builder, string connectionString)
        {
            builder.UseSqlite(connectionString, options => options.MigrationsAssembly(Assembly.GetExecutingAssembly().FullName));
        }
    }
}
