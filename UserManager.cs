
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using Suporte.Controllers;

namespace Suporte.Services
{
    public class UserManager
    {
        private readonly SqlSessionManager _sessionManager;
        private readonly SqlConnection _connection;
        
        public UserManager(SqlSessionManager sessionManager)
        {
            _sessionManager = sessionManager;
            _connection = new SqlConnection();
        }

        
        public async Task UpdatePasswordAsync(string userId, string newPassword)
        {
            var user = await FindByIdAsync(userId);
            var hashedPassword = AuthController.ComputePBKDF2Hash(newPassword);
            user.Password = hashedPassword;
            await UpdateAsync(user);
        }


        public string GeneratePasswordResetToken(int userId)
        {
            var tokenData = new byte[32]; // 256 bits
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(tokenData);
            }
            return Convert.ToBase64String(tokenData);
        }

        public async Task SavePasswordResetTokenAsync(int userId, string token)
        {
            
            if (_connection.State != System.Data.ConnectionState.Open) {                
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }

            var tokenHash = AuthController.ComputePBKDF2Hash(token);

            var expirationTime = DateTime.UtcNow.AddMinutes(30);

            string sql = @"
                INSERT INTO PasswordResetTokens (UserId, TokenHash, ExpirationTime)
                VALUES (@UserId, @TokenHash, @ExpirationTime)";

            using (var command = new SqlCommand(sql, _connection))
            {
                command.Parameters.AddWithValue("@UserId", userId);
                command.Parameters.AddWithValue("@TokenHash", tokenHash);
                command.Parameters.AddWithValue("@ExpirationTime", expirationTime);

                await command.ExecuteNonQueryAsync();
            }
        }

        public async Task<UserInfo> FindByIdAsync(string userId) 
        {
            if (_connection.State != System.Data.ConnectionState.Open) {                
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }

            string sql = @"
                    SELECT U.ID, U.DisplayName, U.Cdate, U.Active, U.Country, U.password, U.Number, U.CountryCode, U.Email
                    FROM [Users] U
                    WHERE (U.ID = @userId)";

            using (var command = new SqlCommand(sql, _connection))
            {

                command.Parameters.Add("@userId", SqlDbType.NVarChar).Value = userId;

                using (var reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        UserInfo userInfo = new UserInfo
                        {
                            User = (int)reader["ID"],
                            Username = Convert.ToString(reader["Username"]),
                            DisplayName = reader["DisplayName"].ToString(),
                            Cdate = Convert.ToDateTime(reader["Cdate"]),
                            Active = Convert.ToBoolean(reader["Active"]),
                            Country = Convert.ToString(reader["Country"]),
                            CountryCode = Convert.ToString(reader["CountryCode"]),
                            Number = Convert.ToString(reader["Number"]),
                            Email = Convert.ToString(reader["Email"]),
                            Password = Convert.ToString(reader["Password"])
                        };
                        reader.Close();
                        return userInfo;
                    }
                    else
                    {
                        reader.Close();
                        return null;
                    }
                }
            }
        }

        public async Task<bool> UpdateAsync(UserInfo user) 
        {
            if (_connection.State != System.Data.ConnectionState.Open) {                
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }

            string sql = @"
                    UPDATE [Users]
                        SET Password = @password
                    WHERE
                        ID = @UserId";

            using (var command = new SqlCommand(sql, _connection))
            {
                command.Parameters.AddWithValue("@UserId", user.User);
                command.Parameters.AddWithValue("@UserId", user.Password);

                await command.ExecuteNonQueryAsync();

                return true;
            }

            return false;
        }

        public async Task<UserInfo> FindByEmailAsync(string email)
        {if (_connection.State != System.Data.ConnectionState.Open) {                
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }

            string sql = @"
                    SELECT U.ID, U.DisplayName, U.Cdate, U.Active, U.Country, U.password, U.Number, U.CountryCode, U.Email
                    FROM [Users] U
                    WHERE (U.Email = @email)";

            using (var command = new SqlCommand(sql, _connection))
            {
                command.Parameters.Add("@email", SqlDbType.NVarChar).Value = email;

                using (var reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        UserInfo userInfo = new UserInfo
                        {
                            User = (int)reader["ID"],
                            Username = Convert.ToString(reader["Username"]),
                            DisplayName = reader["DisplayName"].ToString(),
                            Cdate = Convert.ToDateTime(reader["Cdate"]),
                            Active = Convert.ToBoolean(reader["Active"]),
                            Country = Convert.ToString(reader["Country"]),
                            CountryCode = Convert.ToString(reader["CountryCode"]),
                            Number = Convert.ToString(reader["Number"]),
                            Email = Convert.ToString(reader["Email"]),
                            Password = Convert.ToString(reader["Password"])
                        };
                        reader.Close();
                        return userInfo;
                    }
                    else
                    {
                        reader.Close();
                        return null;
                    }
                }
            }
        }

        public async Task<string> ValidatePasswordResetTokenAsync(string token)
        {
            // Hash the provided token for comparison
            var tokenHash = HashToken(token);

            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.OpenAsync();

                string sql = @"
                    SELECT UserId 
                    FROM PasswordResetTokens 
                    WHERE TokenHash = @TokenHash
                      AND ExpirationTime > @CurrentTime
                      AND IsInvalidated = 0";

                using (var command = new SqlCommand(sql, connection))
                {
                    command.Parameters.AddWithValue("@TokenHash", tokenHash);
                    command.Parameters.AddWithValue("@CurrentTime", DateTime.UtcNow);

                    var result = await command.ExecuteScalarAsync();

                    if (result != null)
                    {
                        return result.ToString();
                    }
                }
            }

            return null;
        }

        public async Task InvalidatePasswordResetTokenAsync(string userId)
        {
            if (_connection.State != System.Data.ConnectionState.Open) {                
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }
        
            string sql = @"
                UPDATE PasswordResetTokens
                SET Valid = 0
                WHERE UserId = @UserId";

            using (var command = new SqlCommand(sql, _connection))
            {
                command.Parameters.AddWithValue("@UserId", userId);
                await command.ExecuteNonQueryAsync();
            }
        }

    }

    public class UserInfo
    {
        public int User { get; set; }
        public string Username { get; set; }
        public string DisplayName { get; set; }
        public string Email { get; set; }
        public string Number { get; set; }
        public string CountryCode { get; set; }
        public DateTime Cdate { get; set; }
        public string Country { get; set; }
        public bool Active { get; set; }
        public string Password { get; set; }
    }
}