using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserService userService;

        public AuthController(IConfiguration configuration, IUserService userService) {
            this._configuration = configuration;
            this.userService = userService;
        }
        [HttpGet,Authorize]
        public ActionResult<string> GetMe()
        {
            var userName = userService.GetMyName();
            return Ok(userName);
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDTO request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Usernmae;
            user.Passwordhash = passwordHash;
            user.PaswwordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDTO request)
        {
            if (user.Username != request.Usernmae)
            {
                return BadRequest("User NotFount");
            }
            if (!VerifyPasswordHash(request.Password, user.Passwordhash, user.PaswwordSalt))
            {
                return BadRequest("Wrong paswword.");
            }

            string token = CreateToken(user);

            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken= Request.Cookies["refreshToken"];
            if(!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token ");
            }
            else if (user.TokenCreated < DateTime.Now)
            {
                return Unauthorized("Token expired.");
            }

            string token= CreateToken(user);
            var newRefreshTokenHash = GenerateRefreshToken();
            SetRefreshToken(newRefreshTokenHash);

            return Ok(token);
        }

        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };

            return refreshToken;
        }
        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };
            Response.Cookies.Append("refreshToken",newRefreshToken.Token,cookieOptions);

            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires= newRefreshToken.Expires;
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,user.Username),
                new Claim(ClaimTypes.Role,"Admin")
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHas, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

                return computedHash.SequenceEqual(passwordHas);
            }
        }
    }
}
