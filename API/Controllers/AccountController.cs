using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{

  public class AccountController : BaseApiController
  {
    private readonly DataContext _context;

    public AccountController(DataContext context)
    {
        _context = context;
    }

    [HttpPost("register")]
    public async Task<ActionResult<AppUser>> Register(RegisterDTO registerDTO)
    {
      if(await UserExists(registerDTO.Username))
      {
        return BadRequest("User Name Is Taken");
      }
      //creating a password hash IDisposable kinda deal
      using var hmac = new HMACSHA512();
      //create a new user
      var user = new AppUser
      {
        UserName = registerDTO.Username.ToLower(),
        PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
        PasswordSalt = hmac.Key

      };
      //does not add to DB just tracks the new local variable
      _context.Users.Add(user);

      //await statement actually calls to teh database and saves the user in to the users table.
      await _context.SaveChangesAsync();
      
      return user;
    }
    [HttpPost("Login")]
    public async Task<ActionResult<AppUser>> Login(LoginDTO loginDTO)
    {
      //making a call to the database 
      var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDTO.Username);
      //handle the exception if user is null or taken
      if(user == null) return Unauthorized("Invalid username");

      using var hmac = new HMACSHA512(user.PasswordSalt);

      var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));
      
      for (int i = 0; i < computedHash.Length; i++)
      {
          if (computedHash[i] != user.PasswordHash[i])
          {
            return Unauthorized("Invalid Password");
          }
      }
      return user;
    }

    private async Task<bool> UserExists(string username)
    {
      return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
    }

  }
}