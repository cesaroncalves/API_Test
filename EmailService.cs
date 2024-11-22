using Microsoft.Data.SqlClient;

namespace Suporte.Services
{
    public class EmailService 
    { 
        private readonly SqlSessionManager _sessionManager;
        private readonly SqlConnection _connection;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public EmailService(SqlSessionManager sessionManager)
        {
            _sessionManager = sessionManager;
            _httpContextAccessor = new HttpContextAccessor();
            _connection = new SqlConnection();
        }

        public async Task SendPasswordRecoveryEmail(string email, string? resetLink)
        {
            throw new NotImplementedException();
        }
    }

}