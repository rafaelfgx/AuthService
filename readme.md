# AuthService

[Identity Server](https://identityserver.io)

## Run

<details>
<summary>Command Line</summary>

#### Prerequisites

* [.NET 5 SDK](https://dotnet.microsoft.com/download/dotnet/5.0)

#### Steps

1. Open directory **source\AuthService** in command line and execute **dotnet run**.
2. Open <https://localhost:5000>.

</details>

<details>
<summary>Visual Studio Code</summary>

#### Prerequisites

* [.NET 5 SDK](https://dotnet.microsoft.com/download/dotnet/5.0)
* [Visual Studio Code](https://code.visualstudio.com)
* [C# Extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.csharp)

#### Steps

1. Open **source** directory in Visual Studio Code.
2. Press **F5**.

</details>

<details>
<summary>Visual Studio</summary>

#### Prerequisites

* [.NET 5 SDK](https://dotnet.microsoft.com/download/dotnet/5.0)
* [Visual Studio](https://visualstudio.microsoft.com)

#### Steps

1. Open **source\AuthService.sln** in Visual Studio.
2. Set **AuthService** as startup project.
3. Press **F5**.

</details>

## Migrations

Add-Migration Identity -c IdentityDbContext -o Migrations/Identity

Add-Migration Configuration -c ConfigurationDbContext -o Migrations/Configuration

Add-Migration PersistedGrant -c PersistedGrantDbContext -o Migrations/PersistedGrant

## API

```cs
public class Startup
{
    public void Configure(IApplicationBuilder application)
    {
        application.UseAuthentication();
        application.UseAuthorization();
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = "https://localhost:5000";
                options.Audience = "api";
            });
    }
}
```

## Angular (Code + PKCE)

### NPM Package: oidc-client

### AppAuthService

```ts
import { Injectable } from "@angular/core";
import { User, UserManager } from "oidc-client";

@Injectable({ providedIn: "root" })
export class AppAuthService {
    private user: User | null | undefined;

    private readonly userManager = new UserManager({
        authority: "https://localhost:5000",
        client_id: "SPA",
        redirect_uri: window.location.origin + "/signin",
        response_type: "code",
        scope: "openid email api"
    });

    constructor() {
        this.userManager.getUser().then((user) => this.user = user);
    }

    signedin() {
        return this.user != null && !this.user.expired;
    }

    signin() {
        return this.userManager.signinRedirect();
    }

    async signinComplete() {
        const user = await new UserManager({ response_mode: "query" }).signinRedirectCallback();
        return this.user = user;
    }

    signout() {
        return this.userManager.signoutRedirect();
    }

    token() {
        return this.user?.access_token;
    }
}
```

### Routes

```ts
export const ROUTES: Routes = [
    {
        path: "",
        pathMatch: "full",
        component: AppHomeComponent,
        canActivate: [AppGuard]
    },
    {
        path: "signin",
        pathMatch: "full",
        component: AppSignInComponent
    }
];
```

### AppSignInComponent

```ts
import { Component, OnInit } from "@angular/core";
import { Router } from "@angular/router";
import { AppAuthService } from "src/app/services/auth.service";

@Component({ selector: "app-signin", template: "" })
export class AppSignInComponent implements OnInit {
    constructor(
        private readonly router: Router,
        private appAuthService: AppAuthService) { }

    async ngOnInit() {
        await this.appAuthService.signinComplete();
        this.router.navigate(["/"]);
    }
}
```

### AppGuard

```ts
import { Injectable } from "@angular/core";
import { CanActivate } from "@angular/router";
import { AppAuthService } from "src/app/services/auth.service";

@Injectable({ providedIn: "root" })
export class AppGuard implements CanActivate {
    constructor(private readonly appAuthService: AppAuthService) { }

    canActivate() {
        if (this.appAuthService.signedin()) { return true; }
        this.appAuthService.signin();
        return false;
    }
}
```

### AppHttpInterceptor

```ts
import { HttpHandler, HttpInterceptor, HttpRequest } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { AppAuthService } from "src/app/services/auth.service";

@Injectable({ providedIn: "root" })
export class AppHttpInterceptor implements HttpInterceptor {
    constructor(private readonly appAuthService: AppAuthService) { }

    intercept(request: HttpRequest<any>, next: HttpHandler) {
        request = request.clone({
            setHeaders: { Authorization: `Bearer ${this.appAuthService.token()}` }
        });

        return next.handle(request);
    }
}
```

## Identity Server Local API

```cs
[Authorize(IdentityServerConstants.LocalApi.PolicyName)]
[Route("/api/controller")]
public class Controller : ControllerBase
{
    public IActionResult Get()
    {
        return Ok();
    }
}
```

## Client

```cs
public class Client
{
    private string Url => "http://localhost:5000";

    public async Task<string> Get()
    {
        var token = await RequestClientCredentialsTokenAsync();

        var http = new HttpClient();

        http.SetBearerToken(token.AccessToken);

        return await http.GetStringAsync($"{Url}/api/controller");
    }

    private async Task<TokenResponse> RequestClientCredentialsTokenAsync()
    {
        using var http = new HttpClient();

        var disco = await http.GetDiscoveryDocumentAsync(Url);

        var request = new ClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = "Client",
            ClientSecret = "Secret",
            Scope = IdentityServerConstants.LocalApi.ScopeName
        };

        return await http.RequestClientCredentialsTokenAsync(request);
    }
}
```
