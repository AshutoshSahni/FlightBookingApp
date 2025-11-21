using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase 
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AccountController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
		}

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] DTOs.RegisterDTO model)
        {
            var user = new IdentityUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                return Ok(new { Message = "User registered successfully" });
            }
            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] DTOs.LoginDTO model)
        {
			var user = await _userManager.FindByEmailAsync(model.Email);
			if (user == null) return Unauthorized("Invalid credentials");

			var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (result.Succeeded)
            {
				var token = await GenerateJwtToken(user);

				// Generate JWT token here (omitted for brevity)
				return Ok(new { Message = "Login successful", Token = token});
            }
            return Unauthorized(new { Message = "Invalid login attempt" });
		}

		private async Task<string> GenerateJwtToken(IdentityUser user)
		{
			var jwtSettings = _configuration.GetSection("Jwt");
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]));
			var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			// claims
			var claims = new List<Claim>
			{
				new Claim(JwtRegisteredClaimNames.Sub, user.Id),
				new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
				new Claim(ClaimTypes.Name, user.UserName ?? "")
			};

			// add role claims
			var roles = await _userManager.GetRolesAsync(user);
			claims.AddRange(roles.Select(r => new Claim(ClaimsIdentity.DefaultRoleClaimType, r)));

			var token = new JwtSecurityToken(
				issuer: jwtSettings["Issuer"],
				audience: jwtSettings["Audience"],
				claims: claims,
				expires: DateTime.UtcNow.AddMinutes(double.Parse(jwtSettings["DurationMinutes"] ?? "60")),
				signingCredentials: creds
			);

			return new JwtSecurityTokenHandler().WriteToken(token);
		}
	}
}
