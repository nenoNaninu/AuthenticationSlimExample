using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

var keyBytes = new byte[64];
RandomNumberGenerator.Fill(keyBytes);

builder.Services
    .AddAuthentication()
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidIssuer = "hoge",
            ValidAudience = "fuga",
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.

app.Map("/", async (HttpContext context) =>
{
    var authResult = await context.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
    var principal = authResult.Principal;
    var identity = principal?.Identity;

    if (identity?.IsAuthenticated ?? false)
    {
        var name = principal!.FindFirst(ClaimTypes.Name)!.Value;
        return $"wellcome {name}";
    }
    else
    {
        var claims = new[] {
            new Claim(ClaimTypes.Name, "sample"),
        };

        var key = new SymmetricSecurityKey(keyBytes);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var header = new JwtHeader(credentials);
        var payload = new JwtPayload("hoge", "fuga", claims, null, DateTime.Now.AddMinutes(1));
        var token = new JwtSecurityToken(header, payload);

        var handler = new JwtSecurityTokenHandler();

        return handler.WriteToken(token);
    }
});

app.Run();
