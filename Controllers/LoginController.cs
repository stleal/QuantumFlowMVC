using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using QuantumFlowMVC.Models;

namespace QuantumFlowMVC.Controllers;

public class LoginController : Controller
{
    private readonly ILogger<LoginController> _logger;
    private readonly IConfiguration _configuration;
    private readonly IHttpClientFactory _httpClientFactory;

    public LoginController(
        ILogger<LoginController> logger,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _configuration = configuration;
        _httpClientFactory = httpClientFactory;
    }

    public IActionResult Index()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Index", "Home");
        }

        return View();
    }

    public IActionResult About()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(string username, string password, bool rememberMe = false)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return RedirectToAction(nameof(Index));
        }

        try
        {
            var client = _httpClientFactory.CreateClient();
            var apiUrl = _configuration["QuantumFlow.API:BaseUrl"] + _configuration["QuantumFlow.API:LoginEndpoint"];
            var response = await client.PostAsJsonAsync(apiUrl, new { Username = username, Password = password });

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Login request failed for user {Username} with status code {StatusCode}.", username, response.StatusCode);
                return RedirectToAction(nameof(Index));
            }
        }
        catch (HttpRequestException exception)
        {
            _logger.LogError(exception, "Login API request failed for user {Username}.", username);
            return RedirectToAction(nameof(Index));
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, username)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = rememberMe,
            RedirectUri = Url.Action("Index", "Home")
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction(nameof(Index));
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}