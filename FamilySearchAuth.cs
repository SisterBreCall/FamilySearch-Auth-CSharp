using JWT;
using System.Net;
using System.Text;
using Newtonsoft.Json;
using JWT.Serializers;
using System.Diagnostics;
using AncestryResource;
using AccessTokenResource;
using CurrentUserResource;
using IdentityTokenResource;
using System.Net.Http.Headers;
using System.Security.Cryptography;

public class FamilySearchAuth
{
    // Set variables with FamilySearch API Key, environment, and redirects
    private string clientID = "";
    private Environment devEnvironment = Environment.Production;
    string redirectUri = "http://127.0.0.1:5000";
    string redirectUriListener = "http://127.0.0.1:5000/";

    private Uri baseUri;
    private string codeVerifier = "";
    private string codeChallenge = "";
    private string responseString = "";
    private bool finishedProcessing = true;
    private string authorizationCode = "";
    private HttpClient httpClient = new HttpClient();
    private AccessTokenJson accessToken;

    private static FamilySearchAuth _instance = new FamilySearchAuth();

    private enum Environment
    {
        Production,
        Beta,
        Integration
    }

    private FamilySearchAuth()
    {

    }

    public static FamilySearchAuth Instance
    {
        get { return _instance; }
    }

    private void SetBaseURL(string setType)
    {
        if (setType == "Auth")
        {
            switch (devEnvironment)
            {
                case Environment.Production:
                    baseUri = new Uri("https://ident.familysearch.org/cis-web/oauth2/v3/authorization");
                    break;
                case Environment.Beta:
                    baseUri = new Uri("https://identbeta.familysearch.org/cis-web/oauth2/v3/authorization");
                    break;
                case Environment.Integration:
                    baseUri = new Uri("https://identint.familysearch.org/cis-web/oauth2/v3/authorization");
                    break;
            }
        }
        else if (setType == "Token")
        {
            switch (devEnvironment)
            {
                case Environment.Production:
                    baseUri = new Uri("https://ident.familysearch.org/cis-web/oauth2/v3/token");
                    break;
                case Environment.Beta:
                    baseUri = new Uri("https://identbeta.familysearch.org/cis-web/oauth2/v3/token");
                    break;
                case Environment.Integration:
                    baseUri = new Uri("https://identint.familysearch.org/cis-web/oauth2/v3/token");
                    break;
            }
        }
        else if (setType == "Regular")
        {
            switch (devEnvironment)
            {
                case Environment.Production:
                    baseUri = new Uri("https://api.familysearch.org/");
                    break;
                case Environment.Beta:
                    baseUri = new Uri("https://apibeta.familysearch.org/");
                    break;
                case Environment.Integration:
                    baseUri = new Uri("https://api-integ.familysearch.org/");
                    break;
            }
        }
    }

    private static string GenerateRandom(uint length)
    {
        byte[] bytes = new byte[length];
        RandomNumberGenerator.Create().GetBytes(bytes);
        return EncodeNoPadding(bytes);
    }

    private static string EncodeNoPadding(byte[] buffer)
    {
        string toEncode = Convert.ToBase64String(buffer);

        toEncode = toEncode.Replace("+", "-");
        toEncode = toEncode.Replace("/", "_");
        toEncode = toEncode.Replace("=", "");

        return toEncode;
    }

    private static byte[] GenerateSha256(string inputString)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(inputString);
        SHA256 sha256 = SHA256.Create();
        return sha256.ComputeHash(bytes);
    }

    public void InitAuth()
    {
        SetBaseURL("Auth");

        codeVerifier = GenerateRandom(32);
        codeChallenge = EncodeNoPadding(GenerateSha256(codeVerifier));

        Random random = new Random();

        int randomState = random.Next(2000000, 3000000);
        string outState = randomState.ToString();

        string authRequest = string.Format("{0}?client_id={1}&redirect_uri={2}&response_type=code&state={3}&code_challenge={4}&code_challenge_method=S256&scope=openid%20profile%20email%20qualifies_for_affiliate_account%20country",
        baseUri,
        clientID,
        redirectUri,
        outState,
        codeChallenge);

        HttpListener httpListener = new HttpListener();
        httpListener.Prefixes.Add(redirectUriListener);

        httpListener.Start();

        Process process = new Process();
        process.StartInfo.FileName = authRequest;
        process.StartInfo.UseShellExecute = true;
        process.Start();

        HttpListenerContext context = httpListener.GetContext();
        HttpListenerResponse response = context.Response;

        string responseString = "<HTML><HEAD><SCRIPT>window.close();</SCRIPT></HEAD><BODY></BODY></HTML>";
        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        response.ContentLength64 = buffer.Length;
        Stream output = response.OutputStream;
        output.Write(buffer, 0, buffer.Length);
        output.Close();

        httpListener.Stop();

        authorizationCode = context.Request.QueryString.Get("code");
        string inState = context.Request.QueryString.Get("state");

        if (inState == outState)
        {
            ExchangeCodeForToken();
            Console.ReadLine();
        }
    }

    private async void ExchangeCodeForToken()
    {
        SetBaseURL("Token");

        Dictionary<string, string> formData = new Dictionary<string, string>();
        formData.Add("code", authorizationCode);
        formData.Add("grant_type", "authorization_code");
        formData.Add("client_id", clientID);
        formData.Add("code_verifier", codeVerifier);

        FormUrlEncodedContent content = new FormUrlEncodedContent(formData);

        httpClient.DefaultRequestHeaders.Accept.Clear();
        httpClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));

        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, baseUri);
        request.Content = content;
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        HttpResponseMessage response = await httpClient.SendAsync(request);

        responseString = await response.Content.ReadAsStringAsync();

        accessToken = JsonConvert.DeserializeObject<AccessTokenJson>(responseString);

        DecodeJWT();
    }

     private void DelayTillProcessed(int seconds)
    {
        do
        {
            Task.Delay(seconds);
        }
        while(!finishedProcessing);
    }

    private void DecodeJWT()
    {
        IJsonSerializer serializer = new JsonNetSerializer();
        IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
        IJwtDecoder decoder = new JwtDecoder(serializer, urlEncoder);

        string jwtString = decoder.Decode(accessToken.id_token, false);

        IdentityJson identityToken = JsonConvert.DeserializeObject<IdentityJson>(jwtString);

        Console.WriteLine($"Hello {identityToken.given_name}");
        Console.WriteLine();
        
        GetCurrentUser();
    }

    public void GetCurrentUser()
    {
        SetBaseURL("Regular");

        SendRequest("platform/users/current");

        DelayTillProcessed(1);

        CurrentUserJson currentUser = JsonConvert.DeserializeObject<CurrentUserJson>(responseString);

        GetAncestry(currentUser.users[0].personId);
    }

    private void GetAncestry(string userPid)
    {
        string endPoint = "platform/tree/ancestry";
        string person = "?person=" + userPid;
        string generations = "&generations=4";
        string apiRequest = $"{endPoint}{person}{generations}";

        SendRequest(apiRequest);

        DelayTillProcessed(1);

        AncestryJson ancestryJson = JsonConvert.DeserializeObject<AncestryJson>(responseString);

        for (int i = 0; i < ancestryJson.persons.Count; i++)
        {
            Console.WriteLine($"{ancestryJson.persons[i].display.name} : {ancestryJson.persons[i].id}");
        }
    }

    private async void SendRequest(string apiRoute)
    {
        finishedProcessing = false;

        string requestString = $"{baseUri}{apiRoute}";

        httpClient.DefaultRequestHeaders.Clear();
        httpClient.DefaultRequestHeaders.Accept.Clear();
        httpClient.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
        httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken.access_token}");
    
        HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestString);

        HttpResponseMessage response = await httpClient.SendAsync(request);
   
        responseString = await response.Content.ReadAsStringAsync();

        finishedProcessing = true;
    }
}
