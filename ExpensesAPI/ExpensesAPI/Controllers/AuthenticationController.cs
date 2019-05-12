using ExpensesAPI.Data;
using ExpensesAPI.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Web.Http;
using System.Web.Http.Cors;

namespace ExpensesAPI.Controllers
{
    [RoutePrefix("auth")]
    [EnableCors("http://localhost:4200", "*", "*")]
    public class AuthenticationController : ApiController
    {
        [HttpPost]
        [Route("login")]
        public IHttpActionResult Login([FromBody] User user)
        {
            if (string.IsNullOrEmpty(user.Username) || string.IsNullOrEmpty(user.Password))
            {
                return BadRequest("Enter Your Username and Password");
            }
            try
            {
                using (var context = new AppDbContext())
                {
                    var exist = context.Users.Any(u => u.Username == user.Username && u.Password == user.Password);
                    if (exist)
                    {
                        return Ok(CreateToken(user));
                    }
                    return BadRequest("Wrong Credential");
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
                
            }
        }

        [HttpPost]
        [Route("register")]
        public IHttpActionResult Register([FromBody] User user)
        {
            try
            {
                using (var context = new AppDbContext())
                {
                    var exist = context.Users.Any(u => u.Username == user.Username);
                    if (exist) return BadRequest("User already Exist");
                    context.Users.Add(user);
                    context.SaveChanges();
                    return Ok(CreateToken(user));
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        private JwtPackage CreateToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claims = new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.Email,user.Username)
            });
            const string secretKey = "Your secret key is here";
            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(secretKey));
            var signinCredential = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var token =(JwtSecurityToken) tokenHandler.CreateJwtSecurityToken(subject: claims, signingCredentials: signinCredential);
            var tokenString = tokenHandler.WriteToken(token);
            return new JwtPackage
            {
                UserName = user.Username,
                Token = tokenString
            };
        }
    }
    public class JwtPackage
    {
        public string Token { get; set; }
        public string UserName { get; set; }
    }
}
