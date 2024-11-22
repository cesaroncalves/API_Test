
using Microsoft.Data.SqlClient;
using Suporte.Services;

var builder = WebApplication.CreateBuilder(args);
SqlConnection connection;

builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen();
builder.Services.AddSwaggerGen(options =>
{
    var xmlFilename = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
});
builder.Services.AddHttpContextAccessor();

GlobalVariables.ConnectionString = builder.Configuration.GetConnectionString("DefaultConnection");

string connectionString = GlobalVariables.ConnectionString;

using (connection = new SqlConnection(connectionString)) 
{ 
    try 
    {
        connection.ConnectionString = connectionString;
        connection.Open(); 
        Console.WriteLine("Connection successful!"); 
    }
    catch (Exception ex) 
    { 
        Console.WriteLine($"Connection failed: {ex.Message}"); 
    } 
}
SqlSessionManager sessionManager = new SqlSessionManager();

builder.Services.AddSingleton(sessionManager);
builder.Services.AddSingleton(new LoginService(sessionManager));
builder.Services.AddSingleton(new RegisterService());
builder.Services.AddSingleton(new SessionCleanupService(sessionManager));
builder.Services.AddSingleton(new EmailService(sessionManager));
builder.Services.AddControllers();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.MapControllers();
app.Run();