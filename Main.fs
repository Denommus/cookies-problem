namespace cookietest

open Owin
open Microsoft.Owin
open Microsoft.Owin.Security.Cookies
open Microsoft.AspNet.Identity

type Startup() =
    member this.Configuration(builder: IAppBuilder) =
        let options = new CookieAuthenticationOptions(LoginPath = new PathString("/"),
                                                      AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                                                      CookieSecure = CookieSecureOption.Always)
        printfn "Test"
        builder.UseCookieAuthentication(options) |> ignore
        builder.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie)
        ()

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
    [<assembly: OwinStartup(typeof<Startup>)>]
    do ()
    open WebSharper.UI.Next.Html
    open System.Web
    open System.Security.Claims
    open Microsoft.Owin.Security

    let getClaims() =
        let claims = [new Claim(ClaimTypes.Email, "foo@bar.com")]
        claims

    let HomePage (ctx : Context<EndPoint>) =
        let owinctx = ctx.Environment.Item "OwinContext" :?> IOwinContext
        printfn "%O" owinctx.Authentication
        owinctx.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie)
        owinctx.Authentication.SignIn(new AuthenticationProperties(IsPersistent = true),
                                      new ClaimsIdentity(getClaims(), DefaultAuthenticationTypes.ApplicationCookie))
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

    let codeBase = Assembly.GetEntryAssembly().CodeBase
    let builder = UriBuilder(codeBase)
    let pathToAssembly = Uri.UnescapeDataString(builder.Path)
    let rootPath = Path.GetDirectoryName(Path.Combine(pathToAssembly, "../../"))
    (*let debugConfig = { defaultConfig with logger = Loggers.saneDefaultsFor LogLevel.Verbose }*)

    do startWebServer defaultConfig (WebSharperAdapter.ToWebPart (Main, RootDirectory=rootPath))

