using System;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;
using System.Data;

namespace Suporte.Services
{
    public class SqlSessionManager
    {
        private readonly SqlConnection _connection;

        public SqlSessionManager()
        {
            _connection = new SqlConnection();
        }

        public async Task<string> CreateSessionAsync(int userId)
        {
            string sessionKey = GenerateSessionKey();
            DateTime expiration = DateTime.UtcNow.AddHours(1); 

            if (_connection.State != System.Data.ConnectionState.Open)
            {
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }

            // SQL to check if the user already has a session, delete it if it exists, and insert a new session
            string sql = @"
                DELETE FROM Sessions WHERE UserId = @UserId;
                INSERT INTO Sessions (SessionKey, UserId, Expiration)
                VALUES (@SessionKey, @UserId, @Expiration);";

            using (var command = new SqlCommand(sql, _connection))
            {
                command.Parameters.AddWithValue("@UserId", userId);
                command.Parameters.AddWithValue("@SessionKey", sessionKey);
                command.Parameters.AddWithValue("@Expiration", expiration);

                await command.ExecuteNonQueryAsync();
            }

            return sessionKey; // Return session key to the client
        }


        public async Task<bool> ValidateSessionAsync(string sessionKey, int userId)
        {
            if (_connection.State != System.Data.ConnectionState.Open) 
            {                
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }

            string sql = @"
                SELECT UserId, Expiration
                FROM Sessions
                WHERE SessionKey = @SessionKey
                AND UserId = @UserId";

            using (var command = new SqlCommand(sql, _connection))
            {
                command.Parameters.AddWithValue("@SessionKey", sessionKey);
                command.Parameters.AddWithValue("@UserId", userId);
                using (var reader = await command.ExecuteReaderAsync())
                {
                    if (await reader.ReadAsync())
                    {
                        DateTime expiration = reader.GetDateTime(reader.GetOrdinal("Expiration"));

                        if (expiration > DateTime.UtcNow)
                        {
                            //string userId = reader.GetInt32("UserId").ToString();
                            reader.Close();
                            return (true); // Session is valid
                        }
                    }
                }
            }
        
            return (false); // Session is invalid or expired
        }

        public async Task<bool> TerminateSessionAsync(string sessionKey, int userId)
        {
            if (_connection.State != System.Data.ConnectionState.Open) 
            {                
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }

            string sql = @"
                DELETE
                FROM Sessions
                WHERE SessionKey = @SessionKey
                AND UserId = @UserId";

            using (var command = new SqlCommand(sql, _connection))
            {
                command.Parameters.AddWithValue("@SessionKey", sessionKey);
                command.Parameters.AddWithValue("@UserId", userId);
                try
                {
                    int rowsAffected = await command.ExecuteNonQueryAsync();
        
                    return rowsAffected > 0;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error terminating session: {ex.Message}");
                    return false; 
                }
                
            }
            return false;
        }

        private static string GenerateSessionKey()
        {
            byte[] key = new byte[32]; // 256-bit key
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return Convert.ToBase64String(key);
        }

        public async Task CleanupExpiredSessionsAsync()
        {   
            if (_connection.State != System.Data.ConnectionState.Open) 
            {                
                _connection.ConnectionString = GlobalVariables.ConnectionString;
                await _connection.OpenAsync();
            }

            string sql = "DELETE FROM Sessions WHERE Expiration < @CurrentTime";
            
            using (var command = new SqlCommand(sql, _connection))
            {
                command.Parameters.AddWithValue("@CurrentTime", DateTime.UtcNow);
                await command.ExecuteNonQueryAsync();
            }
        }
    }

    public class SessionCleanupService : BackgroundService
    {
        private readonly SqlSessionManager _sessionManager;
        private readonly TimeSpan _interval = TimeSpan.FromSeconds(120);

        public SessionCleanupService(SqlSessionManager sessionManager)
        {
            _sessionManager = sessionManager;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await _sessionManager.CleanupExpiredSessionsAsync();
                    Console.WriteLine("Expired sessions cleaned up at: {time}", DateTimeOffset.Now);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message + Environment.NewLine + "Error occurred while cleaning up expired sessions.");
                }

                await Task.Delay(_interval, stoppingToken);
            }
        }
    }
}
