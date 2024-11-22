using System;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Concurrent;
using System.Net;
using Microsoft.AspNetCore.Http;
using Suporte.Controllers;

namespace Suporte.Services
{
    public class LoginService
    {
        private static readonly ConcurrentDictionary<string, (int Attempts, DateTime BlockEndTime)> _failedLoginAttempts 
            = new ConcurrentDictionary<string, (int Attempts, DateTime BlockEndTime)>();
        private const int MaxFailedAttempts = 5;
        private const int BlockDurationMinutes = 5;
        private readonly SqlSessionManager _sessionManager;
        private readonly UserManager _userManager;
        private readonly SqlConnection _connection;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LoginService(SqlSessionManager sessionManager)
        {
            _sessionManager = sessionManager;
            _userManager = new UserManager(sessionManager);
            _httpContextAccessor = new HttpContextAccessor();
            _connection = new SqlConnection();
        }

        public async Task<LoginUserInfo> LoginAsync(string username, string password)
        {
            string userIp = GetClientIp();

            if (IsIpBlocked(userIp))
            {
                //throw new UnauthorizedAccessException("Your IP is temporarily blocked due to multiple failed login attempts.");
                if (_failedLoginAttempts.TryGetValue(userIp, out var attemptInfo)) 
                {
                    LoginUserInfo UserInfo = new LoginUserInfo {
                        User = 0,
                        Username = "blocked",
                        DisplayName = "blocked",
                        Cdate = attemptInfo.BlockEndTime,
                        Country = "NA",
                        Active = false,
                        SessionKey = "Your IP is temporarily blocked due to multiple failed login attempts."
                    };
                    return UserInfo;
                }

                return null;
            }
            else 
            {
                if (_failedLoginAttempts.TryGetValue(userIp, out var attemptInfo)) 
                { 
                    Console.WriteLine($"IP: {userIp}, Attempts: {attemptInfo.Attempts}, Block End Time: {attemptInfo.BlockEndTime}"); 
                } 
                else 
                { 
                    Console.WriteLine($"IP: {userIp} has no recorded attempts."); 
                }

                if (_connection.State != System.Data.ConnectionState.Open) {                
                    _connection.ConnectionString = GlobalVariables.ConnectionString;
                    await _connection.OpenAsync();
                }

                string sql = @"
                    SELECT U.ID, U.DisplayName, U.Cdate, U.Active, U.Country, U.password, U.Number, U.CountryCode, U.Email
                    FROM [Users] U
                    WHERE (U.Username = @username OR U.Email = @email)";

                using (var command = new SqlCommand(sql, _connection))
                {

                    command.Parameters.Add("@username", SqlDbType.NVarChar).Value = username;
                    command.Parameters.Add("@email", SqlDbType.NVarChar).Value = username;

                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync())
                        {
                            
                            if (AuthController.VerifyPassword(password, reader["password"]?.ToString())) 
                            {
                                ResetFailedAttempts(userIp);
                                LoginUserInfo userInfo = new LoginUserInfo
                                {
                                    User = (int)reader["ID"],
                                    Username = username,
                                    DisplayName = reader["DisplayName"].ToString(),
                                    Cdate = Convert.ToDateTime(reader["Cdate"]),
                                    Active = Convert.ToBoolean(reader["Active"]),
                                    Country = Convert.ToString(reader["Country"]),
                                    CountryCode = Convert.ToString(reader["CountryCode"]),
                                    Number = Convert.ToString(reader["Number"]),
                                    Email = Convert.ToString(reader["Email"]),
                                    SessionKey = await _sessionManager.CreateSessionAsync((int)reader["ID"])
                                };
                                reader.Close();
                                return userInfo;
                            }
                            else 
                            {
                                reader.Close();
                                RegisterFailedAttempt(userIp);
                                return null;
                            }
                        }
                        else
                        {
                            reader.Close();
                            RegisterFailedAttempt(userIp);
                            return null;
                        }
                    }
                }
            }
        }

        private void RegisterFailedAttempt(string ip)
        {
            _failedLoginAttempts.AddOrUpdate(ip, key => (1, DateTime.MinValue), (key, old) =>
            {
                int attempts = old.Attempts + 1;
                DateTime blockEndTime = old.BlockEndTime;

                if (attempts >= MaxFailedAttempts)
                {
                    blockEndTime = DateTime.Now.AddMinutes(BlockDurationMinutes);
                    Console.WriteLine($"IP {ip} is blocked until {blockEndTime}.");
                }

                return (attempts, blockEndTime);
            });
        }

        private void ResetFailedAttempts(string ip)
        {
            _failedLoginAttempts.TryRemove(ip, out _);
        }

        private bool IsIpBlocked(string ip)
        {
            if (_failedLoginAttempts.TryGetValue(ip, out var info))
            {
                if (info.BlockEndTime > DateTime.Now)
                {
                    return true;
                }
                
                if (info.Attempts >= MaxFailedAttempts) 
                {
                    _failedLoginAttempts.TryRemove(ip, out _);
                }
            }
            return false;
        }

        private string GetClientIp()
        {
            var context = _httpContextAccessor.HttpContext;
            return context?.Connection.RemoteIpAddress?.ToString() ?? "Unknown IP";
        }
    }

    public class LoginUserInfo
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
        public string SessionKey { get; set; }
    }
}
