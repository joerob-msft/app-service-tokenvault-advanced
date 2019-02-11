using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.Azure.Services.AppAuthentication;
using Dropbox.Api;
using Newtonsoft.Json;
using WebAppTokenVault.Models;
using System.Text;

namespace WebAppTokenVault.Controllers
{
    public class HomeController : Controller
    {
        const string TokenVaultResource = "https://tokenvault.azure.net";
        // static client to have connection pooling
        private static HttpClient client = new HttpClient();

        public async System.Threading.Tasks.Task<ActionResult> Index()
        {
            // SessionID is used to verify that the index, login, and save routes are all part of the same session to prevent phishing attacks
            // This code uses the session id for the token name, but a better approach would be to protect these calls with an authenticated user and manage mapping user to token in this app
            var sessionTokenName = Session.SessionID;

            var azureServiceTokenProvider = new AzureServiceTokenProvider();

            var vaultUrl = $"{ConfigurationManager.AppSettings["tokenResourceUrl"]}";
            var vaultName = $"{ConfigurationManager.AppSettings["vaultName"]}";

            var tokenResourceUrl = $"{vaultUrl}/services/dropbox/tokens/{sessionTokenName}";

            ViewBag.LoginLink = $"{this.Request.Url}vault/{vaultName}/dropbox/{sessionTokenName}/login?PostLoginRedirectUrl={this.Request.Url}vault/{vaultName}/dropbox/{sessionTokenName}/save?vaultUrl={vaultUrl}";

            try
            {
                // Get a token to access Token Vault
                string tokenVaultApiToken = await azureServiceTokenProvider.GetAccessTokenAsync(TokenVaultResource);
                await CreateTokenResourceIfNotExists(sessionTokenName, tokenResourceUrl, tokenVaultApiToken);

                // Get Dropbox token from Token Vault
                var dropboxApiToken = await GetAccessToken(tokenResourceUrl, tokenVaultApiToken);

                ViewBag.Secret = $"Token: {dropboxApiToken.Value?.AccessToken}";

                ViewBag.FileList = await this.GetDocuments(dropboxApiToken.Value?.AccessToken);
            }
            catch (Exception exp)
            {
                ViewBag.FileList = new List<string>();
                ViewBag.Error = $"Something went wrong: {exp.InnerException?.Message}";
            }

            ViewBag.Principal = azureServiceTokenProvider.PrincipalUsed != null ? $"Principal Used: {azureServiceTokenProvider.PrincipalUsed}" : string.Empty;

            return View();
        }

        private static async Task<Token> GetAccessToken(string tokenResourceUrl, string tokenVaultApiToken)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, tokenResourceUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenVaultApiToken);

            var response = await client.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();

            var token = JsonConvert.DeserializeObject<Token>(responseString);
            return token;
        }

        private static async Task CreateTokenResourceIfNotExists(string sessionTokenName, string tokenResourceUrl, string tokenVaultApiToken)
        {
            // PUT on token is required before POST
            var putRequest = new HttpRequestMessage(HttpMethod.Put, tokenResourceUrl)
            {
                Content = new StringContent($"{{ 'name' : '{sessionTokenName}' }}", Encoding.UTF8, "application/json"),
            };

            putRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenVaultApiToken);

            var putResponse = await client.SendAsync(putRequest);
            var putResponseString = await putResponse.Content.ReadAsStringAsync();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        private async Task<List<string>> GetDocuments(string token)
        {
            var filesList = new List<string>();

            if (!string.IsNullOrEmpty(token))
            {
                using (var dbx = new DropboxClient(token))
                {
                    var list = await dbx.Files.ListFolderAsync(string.Empty);

                    // show folders then files
                    foreach (var item in list.Entries.Where(i => i.IsFolder))
                    {
                        filesList.Add($"D  {item.Name}/");
                    }

                    foreach (var item in list.Entries.Where(i => i.IsFile))
                    {
                        filesList.Add($"F  {item.Name}");
                    }
                }
            }

            return filesList;
        }
    }
}