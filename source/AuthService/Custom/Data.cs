using IdentityModel;
using IdentityServer4;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace AuthService
{
    public static class Data
    {
        public static void Seed(this ConfigurationDbContext context)
        {
            if (!context.Clients.Any())
            {
                Clients().ForEach(client => context.Clients.Add(client.ToEntity()));
            }

            if (!context.IdentityResources.Any())
            {
                IdentityResources().ForEach(identityResource => context.IdentityResources.Add(identityResource.ToEntity()));
            }

            if (!context.ApiResources.Any())
            {
                ApiResources().ForEach(apiResource => context.ApiResources.Add(apiResource.ToEntity()));
            }

            if (!context.ApiScopes.Any())
            {
                ApiScopes().ForEach(apiScope => context.ApiScopes.Add(apiScope.ToEntity()));
            }

            context.SaveChanges();
        }

        public static void Seed(this UserManager<IdentityUser> userManager)
        {
            if (userManager.Users.Any())
            {
                return;
            }

            Users().ForEach(user =>
            {
                userManager.CreateAsync(user, "Pass123$").Wait();
                userManager.AddClaimsAsync(user, UsersClaims(user.UserName)).Wait();
            });
        }

        private static List<ApiResource> ApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource(IdentityServerConstants.LocalApi.ScopeName),
                new ApiResource("api")
                {
                    ApiSecrets = { new Secret("secret".Sha512()) },
                    Scopes = { "api" }
                }
            };
        }

        private static List<ApiScope> ApiScopes()
        {
            return new List<ApiScope>
            {
                new ApiScope(IdentityServerConstants.LocalApi.ScopeName),
                new ApiScope("api")
            };
        }

        private static List<Client> Clients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "Client",
                    ClientName = "Client",
                    ClientSecrets = { new Secret("Secret".Sha512()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes =
                    {
                        IdentityServerConstants.LocalApi.ScopeName,
                        "api"
                    }
                },
                new Client
                {
                    ClientId = "SPA",
                    ClientName = "SPA",
                    RedirectUris = { "https://localhost:8080/signin" },
                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes =
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        IdentityServerConstants.LocalApi.ScopeName,
                        "api"
                    },
                    AllowAccessTokensViaBrowser = true,
                    AllowOfflineAccess = true,
                    RequireClientSecret = false
                }
            };
        }

        private static List<IdentityResource> IdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
            };
        }

        private static List<IdentityUser> Users()
        {
            return new List<IdentityUser>
            {
                new IdentityUser
                {
                    UserName = "alice",
                    Email = "alice.smith@email.com",
                    EmailConfirmed = true
                },
                new IdentityUser
                {
                    UserName = "bob",
                    Email = "bob.smith@email.com",
                    EmailConfirmed = true
                }
            };
        }

        private static IEnumerable<Claim> UsersClaims(string username)
        {
            return new Dictionary<string, List<Claim>>
            {
                {
                    "alice",
                    new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Name, "Alice Smith"),
                        new Claim(JwtClaimTypes.GivenName, "Alice"),
                        new Claim(JwtClaimTypes.FamilyName, "Smith")
                    }
                },
                {
                    "bob",
                    new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Name, "Bob Smith"),
                        new Claim(JwtClaimTypes.GivenName, "Bob"),
                        new Claim(JwtClaimTypes.FamilyName, "Smith")
                    }
                }
            }
            .GetValueOrDefault(username);
        }
    }
}
