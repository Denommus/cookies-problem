namespace cookietest

open Owin
open Microsoft.Owin
open Microsoft.Owin.Security.Cookies
open Microsoft.AspNet.Identity

open WebSharper
open WebSharper.Sitelets
open WebSharper.UI.Next
open WebSharper.UI.Next.Server

type EndPoint =
    | [<EndPoint "/">] Home
    | [<EndPoint "/about">] About

module Templating =
    open WebSharper.UI.Next.Html

    type MainTemplate = Templating.Template<"Main.html">

    // Compute a menubar where the menu item for the given endpoint is active
    let MenuBar (ctx: Context<EndPoint>) endpoint : Doc list =
        let ( => ) txt act =
             liAttr [if endpoint = act then yield attr.``class`` "active"] [
                aAttr [attr.href (ctx.Link act)] [text txt]
             ]
        [
            li ["Home" => EndPoint.Home]
            li ["About" => EndPoint.About]
        ]

    let Main ctx action title body =
        Content.Page(
            MainTemplate.Doc(
                title = title,
                menubar = MenuBar ctx action,
                body = body
            )
        )



module Site =
    open WebSharper.UI.Next.Html
    open System.Security.Claims
    open Microsoft.Owin.Builder
    open Suave.Owin
    open Microsoft.Owin.Security.DataProtection
    open global.Owin.Security.AesDataProtectorProvider
    open global.Owin.Security.AesDataProtectorProvider.CrypticProviders

    let authMiddleware =
        let builder = new AppBuilder()
        builder.SetDataProtectionProvider(new AesDataProtectorProvider(new Sha512ManagedFactory(),
                                                                       new Sha256ManagedFactory(),
                                                                       new AesManagedFactory()))
        let options = new CookieAuthenticationOptions(LoginPath = new PathString("/"),
                                                      AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                                                      CookieSecure = CookieSecureOption.SameAsRequest)
        let builder = builder.UseCookieAuthentication(options)
        builder.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie)
        builder.Properties.Add("host.AppName", "Themis")
        printfn "Failing"
        let app = builder.Build()
        printfn "Not failing"
        OwinApp.ofAppFunc "/" app


    let getClaims() =
        let claims = [new Claim(ClaimTypes.Email, "foo@bar.com")]
        claims
    open Microsoft.Owin.Security

    let HomePage (ctx : Context<EndPoint>) =
        printfn "Test"
        let owinctx = ctx.Environment.Item "OwinContext" :?> IOwinContext
        owinctx.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie)
        owinctx.Authentication.SignIn(new AuthenticationProperties(IsPersistent = true),
                                      new ClaimsIdentity(getClaims(), DefaultAuthenticationTypes.ApplicationCookie))
        printfn "%O" (owinctx.Authentication.AuthenticationResponseGrant.Principal.Claims.GetEnumerator())
        let user = new ClaimsPrincipal(owinctx.Authentication.AuthenticationResponseGrant.Principal)
        printfn "%O" System.Web.HttpContext.Current
        Templating.Main ctx EndPoint.Home "Home" [
            h1 [text "Say Hi to the server!"]
            div [client <@ Client.Main() @>]
        ]

    let AboutPage ctx =
        Templating.Main ctx EndPoint.About "About" [
            h1 [text "About"]
            p [text "This is a template WebSharper client-server application."]
        ]

    let Main =
        Application.MultiPage (fun ctx endpoint ->
            match endpoint with
            | EndPoint.Home -> HomePage ctx
            | EndPoint.About -> AboutPage ctx
        )

    open WebSharper.Suave
    open Suave.Web
    open Suave.Logging
    open System
    open System.IO
    open System.Reflection
    open Suave.Operators
    open Suave.WebPart

    let codeBase = Assembly.GetEntryAssembly().CodeBase
    let builder = UriBuilder(codeBase)
    let pathToAssembly = Uri.UnescapeDataString(builder.Path)
    let rootPath = Path.GetDirectoryName(Path.Combine(pathToAssembly, "../../"))
    (*let debugConfig = { defaultConfig with logger = Loggers.saneDefaultsFor LogLevel.Verbose }*)
    let debugConfig = { defaultConfig with logger = Targets.create Verbose [||] }


    do startWebServer debugConfig (choose [WebSharperAdapter.ToWebPart (Main, RootDirectory=rootPath); authMiddleware])
