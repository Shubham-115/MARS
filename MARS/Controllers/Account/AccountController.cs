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
using PortalLib.Framework.Utilities;

namespace MARS.Controllers.Accounts
{
    public class AccountController : Controller
    {
        private readonly DataAccessLayer dal;
        private readonly SecureData secure;
        private readonly TokenGenerate TknG;
        private readonly PortalEncryption encryptdecpt;
        public AccountController()
        {
            dal = new DataAccessLayer();
            secure = new SecureData();
            TknG = new TokenGenerate();
            encryptdecpt = new PortalEncryption();
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
                if (dal.Isexist(signUp.EmailID))
                {
                    TempData["msg"] = "User Already Exist ! Please Login ";
                    return RedirectToAction("Login");
                }
                // string token = TknG.GenerateToken();

                string result = dal.Signup(signUp.EmailID, signUp.MobileNo, signUp.FirstName, signUp.LastName);
                if (result != null)
                {
                    string token = dal.UpdateToken(signUp.EmailID);
                    if (token != null)
                    {
                        token = PortalEncryption.EncryptPassword(token);
                        string Email = PortalEncryption.EncryptPassword(signUp.EmailID.ToString());
                        string link = Url.Action("VerifyEmail", "Account", new { token = token, EmailID = Email }, Request.Scheme);

                        TempData["msg2"] = $@"Registration Successful! <br/>Verification link is valid for 24 hours.<br/> Click below to verify:<br/><br/><a href='{link}' class='btn btn-primary'>Verify Email</a>";
                        return RedirectToAction("VerifyLink");

                    }
                }
                TempData["Error"] = result;
                return View();
            }
            return View(signUp);
        }

        public IActionResult GenereateToken(string EmailID)
        {
            if (EmailID == null)
            {
                return RedirectToAction("Index");
            }
            //string token = Guid.NewGuid().ToString();
            EmailID = PortalEncryption.DecryptPassword(EmailID.ToString());
            string token = dal.UpdateToken(EmailID);
            if (token != null)
            {
                token = PortalEncryption.EncryptPassword(token);
                EmailID = PortalEncryption.EncryptPassword(EmailID.ToString());
                string link = Url.Action("VerifyEmail", "Account", new { token = token, EmailID = EmailID }, Request.Scheme);

                TempData["msg2"] = $"Reset Verifyfication link is valid for 24 hours !<br/>Click below to verify:<br/><a href='{link}'>{link}</a>";
                return RedirectToAction("VerifyLink");
            }

            TempData["Error"] = "Invalid Email ";
            return View();
        }

        public IActionResult Verifylink()
        {
            return View();
        }

        public IActionResult VerifyEmail(string token, string EmailID)
        {
            if (EmailID == null)
            {
                return RedirectToAction("Index");
            }

            if (string.IsNullOrEmpty(token))
                return BadRequest("Invalid token.");


            token = PortalEncryption.DecryptPassword(token);
            EmailID = PortalEncryption.DecryptPassword(EmailID.ToString());
            DateTime tokenTime = dal.VerifyUser(token, EmailID);

            if (tokenTime != DateTime.MinValue)   // Token valid
            {
                TempData["msg1"] = "Verification Successful!";
                return RedirectToAction("ViewMessages");
            }
            else   // Token invalid or expired
            {
                EmailID = PortalEncryption.DecryptPassword(EmailID.ToString());

                if (dal.resetToken(EmailID))
                {
                    // token = PortalEncryption.EncryptPassword(token);
                     EmailID = PortalEncryption.EncryptPassword(EmailID.ToString());
                    TempData["msg1"] = "Link expired or invalid token.";
                    string link1 = Url.Action("GenereateToken", "Account", new { EmailID = EmailID }, Request.Scheme);
                    TempData["Regenerate"] = $"Invalid Verification Token or Time Out!<br/>Click below to Resend link :<br/><a href='{link1}'>{link1}</a>";
                    return RedirectToAction("ViewMessages");
                }
            }
            return View();
        }

        public IActionResult ViewMessages()
        {
            return View();
        }

    }

}
