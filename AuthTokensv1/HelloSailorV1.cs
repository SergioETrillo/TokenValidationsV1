using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.IdentityModel.Protocols;

namespace AuthTokensv1
{
    public static class HelloSailorV1
    {
        [FunctionName("HelloSailorV1")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            log.Info("C# HTTP trigger function processed a request.");

            ClaimsPrincipal claimsPrincipal;
            if ((claimsPrincipal = await AuthValidator.ValidateTokenAsync(req.Headers.Authorization)) == null)
            {
                return req.CreateResponse(HttpStatusCode.Unauthorized);
            }

            var claims = claimsPrincipal.Claims;

            foreach (var claim in claims)
            {
                var subject = claim.Subject;
                var subName = subject.Name;
                bool authenticated = subject.IsAuthenticated;
                var label = subject.Label;
                var claimsSub = subject.Claims;
                var actor = subject.Actor;
            }

            // parse query parameter
            string name = req.GetQueryNameValuePairs()
                .FirstOrDefault(q => string.Compare(q.Key, "name", true) == 0)
                .Value;

            if (name == null)
            {
                // Get request body
                dynamic data = await req.Content.ReadAsAsync<object>();
                name = data?.name;
            }

            var authHeaderScheme = req.Headers.Authorization.Scheme;
            var authHeaderParameter = req.Headers.Authorization.Parameter;

            return name == null
                ? req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a name on the query string or in the request body")
                : req.CreateResponse(HttpStatusCode.OK, "Hello " + name); ;
        }
    }
}
