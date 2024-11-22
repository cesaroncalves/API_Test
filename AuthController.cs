using Microsoft.AspNetCore.Mvc;
using Suporte.Services;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Suporte.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly LoginService _loginService;
        private readonly RegisterService _registerService;
        private readonly SqlSessionManager _sessionManager;
        private readonly UserManager _userManager;
        private readonly EmailService _emailService;

        public AuthController(LoginService loginService, RegisterService registerService, EmailService emailService, SqlSessionManager sessionManager)
        {
            _loginService = loginService;
            _registerService = registerService;
            _sessionManager = sessionManager;
            _emailService = emailService;
            _userManager = new UserManager(sessionManager);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _loginService.LoginAsync(request.Name, request.Pass);
            
            if (user != null)
            {
                return Ok(user);
            }
            else
            {
                return Unauthorized();
            }
        }

        [HttpPost("resgister")]
        public async Task<IActionResult> Register([FromBody] RegisterUserInfo request)
        {
            var user = await _registerService.RegisterAsync(request.Username, request.Password, request.DisplayName, request.Email, request.Number, request.CountryCode,  request.Country);
            
            if (user != null)
            {
                user.Password = ""; // Hide the password in the response
                return Ok(user);
            }
            else
            {
                return Unauthorized();
            }
        }

        [HttpGet("validate-session")]
        public async Task<IActionResult> ValidateSession([FromQuery] ValidateSessionRequest request)
        {
            var isValid = await _sessionManager.ValidateSessionAsync(request.sessionKey, request.userId);

            if (isValid)
            {
                return Ok(new { isValid = true });
            }
            else
            {
                return Unauthorized(new { isValid = false });
            }
        }

        [HttpGet("terminate-session")]
        public async Task<IActionResult> TerminateSession([FromQuery] ValidateSessionRequest request)
        {
            var Removed = await _sessionManager.TerminateSessionAsync(request.sessionKey, request.userId);

            if (Removed)
            {
                return Ok(new { Removed = true });
            }
            else
            {
                return Unauthorized(new { Removed = false });
            }
        }

        [HttpPost("recover-password")]
        public async Task<IActionResult> RecoverPassword([FromBody] RecoverPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user == null)
            {
                return Ok(new { message = "If the email exists, a recovery link has been sent." });
            }

            string token = _userManager.GeneratePasswordResetToken(user.User);

            await _userManager.SavePasswordResetTokenAsync(user.User, token);

            string resetLink = Url.Action("ResetPassword", "Account", new { token }, Request.Scheme);
            await _emailService.SendPasswordRecoveryEmail(user.Email, resetLink);

            return Ok(new { message = "If the email exists, a recovery link has been sent." });
        }


        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var userId = await _userManager.ValidatePasswordResetTokenAsync(request.Token);
            if (userId == null)
            {
                return BadRequest(new { message = "Invalid or expired token." });
            }

            await _userManager.UpdatePasswordAsync(userId, request.NewPassword);

            await _userManager.InvalidatePasswordResetTokenAsync(userId);

            return Ok(new { message = "Password has been reset successfully." });
        }
        
        public static string ComputeMD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2")); // Convert each byte to hex
                }
                return sb.ToString();
            }
        }

        private const int SaltSize = 16; // 128-bit
        private const int HashSize = 32; // 256-bit
        private const int Iterations = 10000;

        public static string ComputePBKDF2Hash(string password)
        {
            //Salt is random data as an additional input for an HASH
            byte[] salt = new byte[SaltSize];
            RandomNumberGenerator.Fill(salt);

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                byte[] hash = pbkdf2.GetBytes(HashSize);

                byte[] hashBytes = new byte[SaltSize + HashSize];
                Array.Copy(salt, 0, hashBytes, 0, SaltSize);
                Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

                return Convert.ToBase64String(hashBytes);
            }
        }

        public static bool VerifyPassword(string password, string storedHash)
        {
            byte[] hashBytes = Convert.FromBase64String(storedHash);

            byte[] salt = new byte[SaltSize];
            Array.Copy(hashBytes, 0, salt, 0, SaltSize);

            byte[] storedHashBytes = new byte[HashSize];
            Array.Copy(hashBytes, SaltSize, storedHashBytes, 0, HashSize);

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                byte[] computedHash = pbkdf2.GetBytes(HashSize);

                return CryptographicOperations.FixedTimeEquals(computedHash, storedHashBytes);
            }
        }
    }

    public class LoginRequest
    {
        [Required]
        public required string Name { get; set; }

        /// <summary>
        /// Password should be an hash (MD5 or SHA-256)
        /// </summary>
        [Required]
        public required string Pass { get; set; }
    }
    
    public class ValidateSessionRequest
    {
        [Required]
        public required int userId { get; set; }
        [Required]
        public required string sessionKey { get; set; }
    }

    public class ResetPasswordRequest
    {
        [Required]
        public string Token { get; set; }
        [Required]
        public string NewPassword { get; set; }
    }

    public class RecoverPasswordRequest
    {
        [Required]
        public string Email { get; set; }
    }



}
