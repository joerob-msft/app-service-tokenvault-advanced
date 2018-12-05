using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Text;
using Microsoft.Azure.Services.AppAuthentication;
using System.Net.Http.Headers;

namespace WebAppTokenVault.Controllers
{
    [RoutePrefix("vault")]
    public class VaultController : Controller
    {
        const string TokenVaultResource = "https://tokenvault.azure.net";
        // static client to have connection pooling
        private static HttpClient _httpClient = new HttpClient();

        public VaultController()
        {
        }

        [HttpGet]
        [Route("{vaultName}/{serviceName}/{tokenName}/save")]
        public async Task<ActionResult> SaveTokenAsync(string vaultName, string serviceName, string tokenName, string vaultUrl, string code)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();

            string apiToken = await azureServiceTokenProvider.GetAccessTokenAsync(TokenVaultResource);

            var request = new HttpRequestMessage(HttpMethod.Post, $"{vaultUrl}/services/{serviceName}/tokens/{tokenName}/save");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
            request.Content = new StringContent(new JObject
                    {
                        {
                            "code", code
                        }
                    }.ToString(),
                    Encoding.UTF8,
                    "application/json");

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                throw new InvalidOperationException($"Failed to commit token. {content}");
            }            

            return Redirect(this.Request.Url.GetLeftPart(UriPartial.Authority));
        }
    }
}