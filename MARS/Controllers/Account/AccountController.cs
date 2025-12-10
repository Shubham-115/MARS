using MARS.DataAccess;
using MARS.DataSecurity;
using MARS.Models;
using MARS.Models.Account;
using BCrypt.Net;

using MARS.Models.Accounts;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using Newtonsoft.Json.Converters;
using NuGet.Common;
using System.Text;
using System.Web;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace MARS.Controllers.Accounts
{
    public class AccountController : Controller
    {
        private readonly DataAccessLayer dal;
        private readonly SecureData secure;
        private readonly TokenGenerate TknG;

        public AccountController()
        {
            dal = new DataAccessLayer();
            secure = new SecureData();
            TknG = new TokenGenerate();
        }


        public IActionResult Index()
        {
            return View();
        }



        // Get singUp Action Method
        public IActionResult SignUp()
        {
            return View();
        }


        // SignUp post Action method
        [HttpPost]
        public IActionResult SignUp(UserSignUp signUp)
        {          

            if (ModelState.IsValid)
            {
              // signUp.EmailID = secure.Encrypt(signUp.EmailID);
              // signUp.MobileNo = secure.Encrypt(signUp.MobileNo);

                if (dal.Isexist(signUp.EmailID))
                {
                    TempData["msg"] = "User Already Exist ! Please Login ";
                    return RedirectToAction("Login");
                }
                // string token = TknG.GenerateToken();
                string token = Guid.NewGuid().ToString();
                string result = dal.Signup(signUp.EmailID, signUp.MobileNo, signUp.FirstName, signUp.LastName, token);


                if (result != null)
                {
                    //string token = TknG.GenerateToken();

                    // dal.setStatus(EmailID, 0);

                    //string token = Guid.NewGuid().ToString();
                    string link = Url.Action("VerifyEmail", "Account", new { token = token }, Request.Scheme);

                    TempData["msg2"] = $"Registration Successful!<br/>Click below to verify:<br/><a href='{link}'>{link}</a>";
                    return RedirectToAction("VerifyLink"); // Or a separate page to show TempData


                    //return RedirectToAction("VerifyEmail");
                }
            }
            return View(signUp);
        }
        public IActionResult Verifylink()
        {
            return View();
        }

        public IActionResult VerifyEmail(string token)
        {
            if (string.IsNullOrEmpty(token))
                return BadRequest("Invalid token.");

            bool isVerified = dal.VerifyUser(token);

            if (isVerified)
            {

                TempData["msg1"] = "Verification Successfull";
                return RedirectToAction("ViewMessages");
            }
            TempData["msg1"] = "Verification failed. Invalid or expired token.";
            return RedirectToAction("ViewMessages");
        }

        public IActionResult ViewMessages()
        {
            return View();
        }

    }

}
