using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Suporte.Controllers;

namespace Suporte.Services
{
    public class RegisterService 
    {
        private readonly SqlConnection _connection;
        
        public RegisterService()
        {
            _connection = new SqlConnection();
        }

        public async Task<RegisterUserInfo> RegisterAsync(string username, string password, string displayName, string email, string number = "", string countryCode = "", string country = "")
        {
            if (_connection.State != ConnectionState.Open)
            {
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }
            RegisterUserInfo registerUserInfo = new RegisterUserInfo
            {
                Username = username,
                DisplayName = displayName,
                Email = email,
                Number = number,
                CountryCode = countryCode,
                Country = country,
                Password = password
            };

            if (!registerUserInfo.Validate(out var errors))
            {
                Console.WriteLine("Validation failed:");
                foreach (var error in errors)
                {
                    Console.WriteLine($"- {error}");
                }
                
                throw new ValidationException(registerUserInfo.CreateValidationErrorMessage(errors));
            }

            string sqlCheck = @"
                SELECT TOP 1 ID, Username, DisplayName, Email, Number, CountryCode, Country
                FROM [dbo].[users]
                WHERE Username = @username OR Email = @email";

            string sqlInsert = @"
                INSERT INTO [dbo].[users] 
                    (Username, DisplayName, Email, Number, CountryCode, Country, CDate, Active, [2FA], Password)
                OUTPUT INSERTED.Username, INSERTED.DisplayName, INSERTED.Email, INSERTED.Number, INSERTED.CountryCode, INSERTED.Country
                VALUES 
                    (@username, @displayName, @email, @number, @countryCode, @country, GETDATE(), 0, 0, @password)";

            using (var command = new SqlCommand(sqlCheck, _connection))
            {
                command.Parameters.Add("@username", SqlDbType.NVarChar).Value = username;
                command.Parameters.Add("@email", SqlDbType.NVarChar).Value = email;

                using (var reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        return null;
                    }
                }
            }

            using (var command = new SqlCommand(sqlInsert, _connection))
            {
                password = AuthController.ComputePBKDF2Hash(password);
                command.Parameters.Add("@username", SqlDbType.NVarChar).Value = username;
                command.Parameters.Add("@displayName", SqlDbType.NVarChar).Value = displayName;
                command.Parameters.Add("@email", SqlDbType.NVarChar).Value = email;
                command.Parameters.Add("@number", SqlDbType.Int).Value = number;
                command.Parameters.Add("@countryCode", SqlDbType.NVarChar).Value = countryCode;
                command.Parameters.Add("@country", SqlDbType.NVarChar).Value = country;
                command.Parameters.Add("@password", SqlDbType.NVarChar).Value = password;

                using (var reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                       registerUserInfo.Username = reader["Username"].ToString();
                       registerUserInfo.DisplayName = reader["DisplayName"].ToString();
                       registerUserInfo.Email = reader["Email"].ToString();
                       registerUserInfo.Number = reader["Number"].ToString();
                       registerUserInfo.CountryCode = reader["CountryCode"]?.ToString();
                       registerUserInfo.Country = reader["Country"]?.ToString();
                       registerUserInfo.Password = "";
                    }
                }
            }

            return registerUserInfo;
        }
    }

    public class RegisterUserInfo
    {
        /// <summary>
        /// The username of the user. Must be at least 5 characters long and contain only letters and numbers.
        /// </summary>
        [Required]
        [MinLength(5, ErrorMessage = "Username must be at least 5 characters long.")]
        [RegularExpression(@"^[a-zA-Z0-9]+$", ErrorMessage = "Username can only contain letters and numbers.")]
        public required string Username { get; set; }

        /// <summary>
        /// An optional display name for the user. Must be at least 3 characters long.
        /// </summary>
        [MinLength(3, ErrorMessage = "DisplayName must be at least 3 characters long.")]
        public string? DisplayName { get; set; }

        /// <summary>
        /// The user's email address. Must be valid and at least 6 characters long.
        /// </summary>
        [Required]
        [MinLength(6, ErrorMessage = "Email must be at least 6 characters long.")]
        [EmailAddress(ErrorMessage = "Email must be a valid email address.")]
        public required string Email { get; set; }

        /// <summary>
        /// An optional phone number for the user.
        /// </summary>
        public string? Number { get; set; }
        /// <summary>
        /// Optional country code for the user. (+44, +351, etc...)
        /// </summary>        
        public string? CountryCode { get; set; }
        /// <summary>
        /// Optional country abbreviation (GB, PT, etc...)
        /// </summary>        
        public string? Country { get; set; }
        
        /// <summary>
        /// The hashed password of the user. 
        /// Must be a valid MD5 (32 hexadecimal characters) or SHA-256 (64 hexadecimal characters) hash.
        /// </summary>
        [Required]
        [HashValidation]
        [MinLength(32, ErrorMessage = "Password must be an hash (MD5 or SHA-256).")]
        public required string Password { get; set; }

        //[RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{6,}$", ErrorMessage = "Password must contain at least 6 characters, including an uppercase letter, a lowercase letter, a number, and a symbol.")]
        public bool Validate(out List<ValidationResult> validationErrors)
        {
            var context = new ValidationContext(this);
            var results = new List<ValidationResult>();
            validationErrors = new List<ValidationResult>();

            bool isValid = Validator.TryValidateObject(this, context, results, true);
            validationErrors = results;

            return isValid;
        }

        public string CreateValidationErrorMessage(List<ValidationResult> results)
        {
            return string.Join("; ", results.ConvertAll(result => result.ErrorMessage));
        }
    }

    public class HashValidationAttribute : ValidationAttribute
    {
        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value is not string passwordHash)
            {
                return new ValidationResult("Password must be a hash.");
            }

            if (IsMd5Hash(passwordHash) || IsSha256Hash(passwordHash))
            {
                return ValidationResult.Success;
            }

            return new ValidationResult("Password must be a valid MD5 (32 hex characters) or SHA-256 (64 hex characters) hash.");
        }

        private bool IsMd5Hash(string hash)
        {
            return hash.Length == 32 && Regex.IsMatch(hash, @"^[a-fA-F0-9]+$");
        }

        private bool IsSha256Hash(string hash)
        {
            return hash.Length == 64 && Regex.IsMatch(hash, @"^[a-fA-F0-9]+$");
        }
    }
}