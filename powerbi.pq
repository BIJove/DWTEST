[Version = "1.0.2"]
section DocuWareRefreshTest;

// When set to true, additional trace information will be written out to the User log.
// This should be set to false before release. Tracing is done through a call to
// Diagnostics.LogValue(). When EnableTraceOutput is set to false, the call becomes a
// no-op and simply returns the original value.
EnableTraceOutput = false;

EnableAPIKey = false;

// Native client flow (PKCE)
// see https://tools.ietf.org/html/rfc7636
// see https://oauth.net/2/pkce/
// This is the expected Redirect URI for OAuth flows to work in the Power BI service.
redirect_uri = "https://oauth.powerbi.com/views/oauthredirect.html";

client_id = Text.FromBinary(Extension.Contents("client_id"));

// The sample provides two code_challenge_method examples: "plain" and "S256".
code_challenge_method = "S256";

// Other OAuth settings
windowWidth = 720;
windowHeight = 1024;

//
// Exported functions
//
// These functions are exported to the M Engine (making them visible to end users), and associates
// them with the specified Data Source Kind. The Data Source Kind is used when determining which
// credentials to use during evaluation. Credential matching is done based on the function's parameters.
// All data source functions associated to the same Data Source Kind must have a matching set of required
// function parameters, including type, name, and the order in which they appear.
[DataSource.Kind = "DocuWareRefreshTest", Publish = "DocuWareRefreshTest.Publish"]
shared DocuWareRefreshTest.Contents = Value.ReplaceType(DocuWareRefreshTest.ContentLoad, DocuWareRefreshTestType);
// type function (url as Uri.Type) as any
//
//
// Data Source definition
//
DocuWareRefreshTest = [
    TestConnection = (dataSourcePath) => {"DocuWareRefreshTest.Contents", dataSourcePath},
    Authentication = [
        OAuth = [
            StartLogin = StartLogin,
            FinishLogin = FinishLogin,
            Refresh = Refresh,
            Label = Extension.LoadString("AuthenticationLabel")
        ]
    ]
];

DocuWareRefreshTestType = type function (  
        url as (Uri.Type meta [
        Documentation.FieldCaption = Extension.LoadString("DataSourceUrl"),
        Documentation.FieldDescription = Extension.LoadString("DataSourceUrlDescription"),
        Documentation.SampleValues = {"https://example.docuware.cloud/DocuWare/Search/FileCabinets/96c2e2be-2dab-46e0-a58d-efb8b468e2db/Documents/QueryDocuments"}
    ]))
    as table meta [
        Documentation.Name = Extension.LoadString("Product")
    ];

//
// UI Export definition
//
DocuWareRefreshTest.Publish = [
    Beta = false,
    ButtonText = {"DocuWareRefreshTest", Extension.LoadString("Product")},
    SourceImage = DocuWare.Icons,
    SourceTypeImage = DocuWare.Icons,
    Category = "Online Services"
];

DocuWare.Icons = [
    Icon16 = {
        Extension.Contents("DocuWare16.png"),
        Extension.Contents("DocuWare20.png"),
        Extension.Contents("DocuWare24.png"),
        Extension.Contents("DocuWare32.png")
    },
    Icon32 = {
        Extension.Contents("DocuWare32.png"),
        Extension.Contents("DocuWare40.png"),
        Extension.Contents("DocuWare48.png"),
        Extension.Contents("DocuWare64.png")
    }
];

DocuWareRefreshTest.ContentLoad = (url as text) =>
    let
        // Check if the URL already contains the format=Csv parameter or format=Json
        url = if Text.Contains(url, "format=Json", Comparer.OrdinalIgnoreCase) then
            Text.Replace(url, "format=Json", "format=Csv")
        else if not Text.Contains(url, "format=Csv", Comparer.OrdinalIgnoreCase) then
            url & "?format=Csv"
        else
            url,
        
        Credential = Extension.CurrentCredential(),
        Headers = [
            Accept="application/json"
        ],
        Options = [
            Headers = Headers
        ],
        content = Diagnostics.LogValue("content", Web.Contents(url, Options))
    in
        content;

ExtractBaseUrl = (resourceUrl) =>
let 
    urlParts = Uri.Parts(resourceUrl),
    urlAsTable = Record.ToTable(urlParts),
    parts = urlAsTable[Value],
    schema = parts{0},
    host = parts{1},
    path = parts{3},
    realHost = if host <> "global.dwapi.net" then host else host & Text.Start(path, 37),
    baseUrl = schema
            & "://"
            & realHost
in
    baseUrl;

ExtractIdentityServiceBaseUrl = (resourceUrl) =>
let 
    Headers = [
        Accept="application/json"
    ],
    BaseUrl = ExtractBaseUrl(resourceUrl),
    Options = [
        RelativePath = "/DocuWare/Platform/Home/IdentityServiceInfo",
        Headers = Headers,
        Query = [
            lang = "en"
        ]
    ],
    identityResponse = Web.Contents(BaseUrl, Options),
    json = Json.Document(identityResponse),
    url = json[IdentityServiceUrl],
    oauthUrl = url & "/connect/"
in
    oauthUrl;

//
// OAuth2 flow definition
//
StartLogin = (resourceUrl, state, display) =>
    let
        // We'll generate our code verifier using Guids
        plainTextCodeVerifier = Text.NewGuid() & Text.NewGuid(),
        codeVerifier =
            if (code_challenge_method = "plain") then
                plainTextCodeVerifier
            else if (code_challenge_method = "S256") then
                Base64Url.Encode(Crypto.CreateHash(CryptoAlgorithm.SHA256, Text.ToBinary(plainTextCodeVerifier)))
            else
                error "Unexpected code_challenge_method",
        oauthBase = ExtractIdentityServiceBaseUrl(resourceUrl),
        tokenUrl = Uri.Combine(oauthBase, "token"),
        authorizeUrl = Uri.Combine(oauthBase, "authorize")
            & "?"
            & Uri.BuildQueryString(
                [
                    client_id = client_id,
                    response_type = "code",
                    code_challenge_method = code_challenge_method,
                    code_challenge = codeVerifier,
                    state = state,
                    redirect_uri = redirect_uri,
                    scope = "docuware.platform dwprofile openid"
                ]
            )
    in
        [
            LoginUri = authorizeUrl,
            CallbackUri = redirect_uri,
            WindowHeight = windowHeight,
            WindowWidth = windowWidth,
            // Need to roundtrip this value to FinishLogin
            Context = 
            [
                codeVerifier = plainTextCodeVerifier,
                TokenUrl = tokenUrl
            ]            
        ];

// The code verifier will be passed in through the context parameter.
FinishLogin = (context, callbackUri, state) =>
    let
        Parts = Uri.Parts(callbackUri)[Query]
    in
        TokenMethod(Parts[code], "authorization_code", context);

// Verifier is optional to support both the original FinishLogin call
// (which has a verifier) and the Refresh call (which does not).
TokenMethod = (code, grant_type, optional context) =>
    let
        codeVerifier = if (context[codeVerifier] <> null) then [code_verifier = context[codeVerifier]] else [],
        codeParameter = if (grant_type = "authorization_code") then [code = code] else [refresh_token = code],
        query = codeVerifier
            & codeParameter
            & [
                client_id = client_id,
                // Native client flows should not require a client_secret when using PKCE, but some still do.
                // client_secret = client_secret,
                grant_type = grant_type,
                redirect_uri = redirect_uri
            ],
        ManualHandlingStatusCodes = {},
        Response = Web.Contents(
            context[TokenUrl],
            [
                Content = Text.ToBinary(Uri.BuildQueryString(query)),
                Headers = [
                    #"Content-type" = "application/x-www-form-urlencoded",
                    #"Accept" = "application/json"
                ],
                ManualStatusHandling = ManualHandlingStatusCodes
            ]
        ),
        Parts = Json.Document(Response)
    in
        // check for error in response
        if (Parts[error]? <> null) then
            error Error.Record(Parts[error], Parts[message]?)
        else
            Parts;

Refresh = (resourceUrl, refresh_token) => TokenMethod(refresh_token, "refresh_token");

Base64Url.Encode = (s) => Text.Replace(Text.Replace(Text.BeforeDelimiter(Binary.ToText(s,BinaryEncoding.Base64),"="),"+","-"),"/","_");

Extension.LoadFunction = (name as text) =>
    let
        binary = Extension.Contents(name), asText = Text.FromBinary(binary)
    in
        Expression.Evaluate(asText, #shared);

// Diagnostics module contains multiple functions. We can take the ones we need.
Diagnostics = Extension.LoadFunction("Diagnostics.pqm");

Diagnostics.LogValue = if (EnableTraceOutput) then Diagnostics[LogValue] else (prefix, value) => value;
