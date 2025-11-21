using backend.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using backend;

var builder = WebApplication.CreateBuilder(args);

// ----- DbContext & Identity -----
var connectionString = builder.Configuration.GetConnectionString("Default");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
	options.UseSqlServer(connectionString));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
	options.Password.RequireDigit = true;
	options.Password.RequireLowercase = true;
	options.Password.RequireNonAlphanumeric = false;
	options.Password.RequireUppercase = true;
	options.Password.RequiredLength = 6;
})
	.AddEntityFrameworkStores<ApplicationDbContext>()
	.AddDefaultTokenProviders();

// ----- JWT Authentication -----
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Key"]);

builder.Services.AddAuthentication(options =>
{
	options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
	options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
	options.RequireHttpsMetadata = true;
	options.SaveToken = true;

	options.TokenValidationParameters = new TokenValidationParameters
	{
		ValidateIssuer = true,
		ValidateAudience = true,
		ValidateLifetime = true,
		ValidateIssuerSigningKey = true,
		ValidIssuer = jwtSettings["Issuer"],
		ValidAudience = jwtSettings["Audience"],
		IssuerSigningKey = new SymmetricSecurityKey(key),
		ClockSkew = TimeSpan.FromMinutes(2)

	};
});

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddSwaggerGen();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
	var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
	var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

	// Add admin role if it doesn't exist
	if (!await roleManager.RoleExistsAsync("Admin"))
	{
		await roleManager.CreateAsync(new IdentityRole("Admin"));
	}

	// seed an admin user here if needed.
	string adminUsername = builder.Configuration["Admin:Username"];
	string adminEamil = builder.Configuration["Admin:Email"];
	string adminPassword = builder.Configuration["Admin:Password"];

	if (await userManager.FindByEmailAsync(adminEamil) == null)
	{
		var adminUser = new IdentityUser
		{
			UserName = adminUsername,
			Email = adminEamil,
			EmailConfirmed = true
		};
		var result = await userManager.CreateAsync(adminUser, adminPassword);
		if (result.Succeeded)
		{
			await userManager.AddToRoleAsync(adminUser, "Admin");
		}
		else
		{
			throw new Exception("Failed to create admin user: " + string.Join(", ", result.Errors.Select(e => e.Description)));
		}
	}

}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", context =>
{
	context.Response.Redirect("/swagger");
	return Task.CompletedTask;
});

app.MapControllers();

app.Run();
