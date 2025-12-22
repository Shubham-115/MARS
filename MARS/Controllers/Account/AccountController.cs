using BCrypt.Net;
using MARS.CreateFilters;
using MARS.DataAccess;
using MARS.DataSecurity;
using MARS.Models;
using MARS.Models.Account;
using MARS.Models.Accounts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using Newtonsoft.Json.Converters;
using NuGet.Common;
using PortalLib.Framework.Utilities;
using System.Text;
using System.Web;
using static System.Net.WebRequestMethods;

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
        [HttpGet]
        public IActionResult SignUp()
        {
            return View();
        }


        // SignUp post Action method
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult SignUp(UserSignUp signUp)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            if (dal.IsMobileExist(signUp.MobileNo))
            {
                if (!dal.isVerifiedMobile(signUp.MobileNo))
                {
                    TempData["msg"] = "User Already Exist !";
                    TempData["notVerify"] = "Mobile is not verified please verify";
                    return RedirectToAction("SignUp");
                }
                TempData["msg"] = "User Already Exist ! Please Login ";
                return RedirectToAction("signUp");
            }
            if (dal.IsexistEmail(signUp.EmailID))
            {

                if (!dal.isVerified(signUp.EmailID))
                {
                    string token = dal.UpdateToken(signUp.EmailID);
                    if (token != null)
                    {
                        token = PortalEncryption.EncryptPassword(token);
                        string Email = PortalEncryption.EncryptPassword(signUp.EmailID.ToString());
                        string link = Url.Action("VerifyEmail", "Account", new { token = token, EmailID = Email }, Request.Scheme);

                        TempData["msg2"] = $@"Your are already Registered Please Veirfy ! <br/>Verification link is valid for 24 hours.<br/> Click below to verify:<br/><br/><a href='{link}' class='btn btn-primary'>Verify Email</a>";
                        return RedirectToAction("VerifyLink");

                    }
                    return RedirectToAction("VerifyEmail");
                }

                if (!dal.isVerifiedMobile(signUp.MobileNo))
                {
                    TempData["notVerify"] = "Mobile is not verified please verify";
                    return RedirectToAction("VerifyMobile");
                }

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
                EmailID = PortalEncryption.EncryptPassword(EmailID.ToString());

                string link1 = Url.Action("VerifyMobile", "Account", Request.Scheme);
                TempData["EmailSuccess"] = " Email Verification Successful <br/>";
                HttpContext.Session.SetString("EmailID", EmailID);

                return RedirectToAction("VerifyMobile");
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




        [SessionAuthorize]
        public IActionResult VerifyMobile()
        {
            return View();
        }




        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult VerifyMobile(VerifyMobile mob, string ActionType)
        {
            string EmailID = HttpContext.Session.GetString("EmailID");
            if (EmailID == null)
            {
                return RedirectToAction("VerifyEmail");
            }
            if (ActionType == "Send_OTP")
            {
                ModelState.Remove("OTP");
                if (!ModelState.IsValid)
                {
                    return View(mob);
                }
                EmailID = PortalEncryption.DecryptPassword(EmailID.ToString());
                if (dal.IsValidEmailAndMobile(EmailID, mob.MobileNo))
                {
                    string otp = dal.GetOTP(mob.MobileNo);

                    TempData["OTP"] = otp;
                    //HttpContext.Session.SetString("mobileNo", mob.MobileNo);
                    TempData["msgOTP"] = "Otp Send SuccessFully";
                    return View(mob);
                }
                else
                {

                    TempData["Error"] = "Mobile number is not Exist";
                    return View();
                }
            }

            if (ActionType == "Submit")
            {
                if (!ModelState.IsValid)
                {
                    return View(mob);
                }

                if (!dal.IsMobileExist(mob.MobileNo))
                {
                    TempData["Error"] = "Mobile number is not Exist";
                    return View();
                }
                DateTime OTPTime = dal.VerifyOTP(mob.OTP, mob.MobileNo);
                if (OTPTime != DateTime.MinValue)   // Token valid
                {
                    TempData["msg2"] = $" Mobile Verification Successful ";

                    EmailID = PortalEncryption.DecryptPassword(EmailID.ToString());
                    string password = dal.GenerateRandomString(8);
                    if (dal.SetPassWord(EmailID, password))
                    {

                        EmailID = PortalEncryption.EncryptPassword(EmailID.ToString());
                        password = PortalEncryption.EncryptPassword(password.ToString());
                        string link = Url.Action("VerifyPassword", "Account", new { EmailID = EmailID, Password = password }, Request.Scheme);

                        TempData["Verify"] = $@"Click here to Change Password ! <br/>Verification link is valid for 24 hours.<br/> Click below to verify:<br/><br/><a href='{link}'>Change Password</a>";
                        return RedirectToAction("ViewMessages");
                    }

                }
                else
                {
                    TempData["msg2"] = "OTP Expired Click to Resend OTP ";
                    return View(mob);
                }
            }

            return View(mob);
        }





        public IActionResult VerifyPassword(string EmailID, string Password)
        {
            EmailID = PortalEncryption.DecryptPassword(EmailID.ToString());
            Password = PortalEncryption.DecryptPassword(Password.ToString());
            Password = dal.ConvertHashPassword(Password);
            if (dal.VerifyEmailPassword(EmailID, Password))
            {
                HttpContext.Session.SetString("EmailID", EmailID);
                return RedirectToAction("Passwordchange");

            }
            // return RedirectToAction("Verify");
            return View();
        }



        [AllowAnonymous]
        public IActionResult Login()
        {

            return View();
        }





        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(UserLogin login)
        {

            if (ModelState.IsValid)
            {

                //login.EmailID = secure.Encrypt(login.EmailID);
                string Email = login.EmailID;

                if (!dal.Isexist(login))
                {

                    TempData["NotFound"] = "User Not Registered ...  ! please Register";
                    return RedirectToAction("Login");
                }

                if (!dal.isVerified(Email))
                {
                    string token = dal.UpdateToken(Email);
                    if (token != null)
                    {
                        token = PortalEncryption.EncryptPassword(token);
                        Email = PortalEncryption.EncryptPassword(Email.ToString());
                        string link = Url.Action("VerifyEmail", "Account", new { token = token, EmailID = Email }, Request.Scheme);

                        TempData["msg2"] = $@"Registration Successful! <br/>Verification link is valid for 24 hours.<br/> Click below to verify:<br/><br/><a href='{link}' class='btn btn-primary'>Verify Email</a>";
                        return RedirectToAction("VerifyLink");

                    }
                }

                // convert the plain password string to HashPassword string
                string Password = dal.ConvertHashPassword(login.Password);

                if (dal.VerifyEmailPassword(login.EmailID, Password))
                {
                    HttpContext.Session.SetString("EmailID", Email);
                    dal.UpdateLoginTime(Email);

                    return RedirectToAction("Dashbord");
                }
                else
                {
                    TempData["Error"] = "Invalid Email and Password";
                    return RedirectToAction("Login");
                }
            }
            return View("login");
        }





        public IActionResult ViewMessages()
        {
            return View();
        }





        public IActionResult ForgotPassword()
        {
            // return RedirectToAction("Verify");
            return View();
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
        public IActionResult ForgotPassword(ForgotPassword fp)
        {
            if (ModelState.IsValid)
            {

                // fp.EmailID = secure.Encrypt(fp.EmailID);
                // fp.MobileNo = secure.Encrypt(fp.MobileNo);
                if (dal.IsValidEmailAndMobile(fp.EmailID, fp.MobileNo))
                {
                    //HttpContext.Session.SetString("EmailID", fp.EmailID);
                    dal.setStatus(fp.EmailID, 0);
                    string token = dal.UpdateToken(fp.EmailID);
                    if (token != null)
                    {
                        token = PortalEncryption.EncryptPassword(token);
                        string Email = PortalEncryption.EncryptPassword(fp.EmailID.ToString());
                        string link = Url.Action("VerifyEmail", "Account", new { token = token, EmailID = Email }, Request.Scheme);

                        TempData["msg2"] = $@"Registration Successful! <br/>Verification link is valid for 24 hours.<br/> Click below to verify:<br/><br/><a href='{link}' class='btn btn-primary'>Verify Email</a>";
                        return RedirectToAction("VerifyLink");

                    }
                }
                else
                {
                    TempData["NotExist"] = "Please Enter Correct Email and Mobile Number";
                    return View();
                }
                //return View();
            }
            return View();
        }





        [SessionAuthorize]
        public IActionResult Passwordchange()
        {


            return View();

        }




        [HttpPost]
        [ValidateAntiForgeryToken]
        [SessionAuthorize]
        public IActionResult Passwordchange(PasswordChange passChange)
        {
            if (ModelState.IsValid)
            {
                string EmailID = HttpContext.Session.GetString("EmailID");
                if (EmailID == null)
                {

                }
                if (passChange.PasswordHash != passChange.ConfirmPassword)
                {
                    ViewData["MissMatch"] = " Password does not match ";
                    return View();
                }



                string result = dal.PassWordChange(EmailID, passChange.PasswordHash);
                TempData["SuccessChange"] = result;
                dal.setStatus(EmailID, 1);
                return RedirectToAction("Dashbord");
            }

            return View();

        }






        [SessionAuthorize]
        public IActionResult Dashbord()
        {
            // string Encryptemail = HttpContext.Session.GetString("EmailID");
            // string email = secure.Decript(Encryptemail);
            string email = HttpContext.Session.GetString("EmailID");


            if (email == null)
            {
                TempData["Failed"] = " Please Enter Your Email ";
                return RedirectToAction("Login");
            }

            if (!dal.UserStatus(email))
            {

                TempData["ChangePassword"] = "Please Change your Password first";
                HttpContext.Session.SetString("EmailID", email);

                return RedirectToAction("PasswordChange");
            }
            ViewBag.EmailID = email;
            HttpContext.Session.SetString("EmailID", email);
            return View();
        }





        public IActionResult LogOut()
        {
            string email = HttpContext.Session.GetString("EmailID");
            // dal.setStatus(email, 0);
            HttpContext.Session.Clear();

            return RedirectToAction("Login");

        }
    }
}
