using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace spnegoserver.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        private readonly ILogger<TestController> _logger;

        public TestController(ILogger<TestController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IEnumerable<string> Get()
        {
            var handler = new HttpClientHandler();
            handler.Credentials = new NetworkCredential("user", "password");
            var client = new HttpClient(handler);
            HttpResponseMessage response = client.GetAsync("http://localhost:5000/test/auth").Result;
            string body = response.Content.ReadAsStringAsync().Result;
            return new List<String>()  
            {  
                $"{body}",
            };  
        }
        
        [Authorize]
        [Route("auth")]
        [HttpGet]
        public IEnumerable<string> GetWithAuth()
        {
            return new List<String>()  
            {  
                "Auth1",
            };  
        }
    }
}
