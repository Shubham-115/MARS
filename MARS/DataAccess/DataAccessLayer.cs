using Humanizer.Localisation.DateToOrdinalWords;
using MARS.Models.Account;
using MARS.Models.Accounts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using NuGet.Common;
using NuGet.Protocol;
using System.Data;
using System.Globalization;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;

namespace MARS.DataAccess
{
    public class DataAccessLayer
    {
        public string cs = StringConnection.dbcs;

        // write a functio SignUp for registration afeter verification 
        public string Signup(string EmailID, string MobileNo, string FirstName, string LastName)
        {
           
            using (SqlConnection con = new SqlConnection(cs))
            {
                string query = "INSERT INTO dbo.Users (MobileNo, EmailID, EmailVerified,MobileVerified,FirstName,LastName,Status) VALUES (@MobileNo, @EmailID,@EmailVerified,@MobileVerified,@FirstName,@LastName,@Status)";
                SqlCommand cmd = new SqlCommand(query, con);

                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@FirstName", FirstName);
                cmd.Parameters.AddWithValue("@LastName", LastName);
                cmd.Parameters.AddWithValue("@MobileNo", MobileNo);
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                cmd.Parameters.AddWithValue("@EmailVerified", 0);
                cmd.Parameters.AddWithValue("@MobileVerified", 0);              
                cmd.Parameters.AddWithValue("@Status", 0);
               
                con.Open();

                try
                {
                    cmd.ExecuteNonQuery();
                }
                catch (SqlException ex)
                {
                    // SQL Server unique constraint error number
                    if (ex.Number == 2627 || ex.Number == 2601)
                    {
                        return "You already registered Please login!";
                    }
                    return "Database error: " + ex.Message;
                }
               
            }           
            return "Registration SuccessFull";
        }



        // write a function to check wether the user exist at the signUp time
        public bool Isexist(string EmailID)
        {
            using (SqlConnection con = new SqlConnection(cs))
            {
                string query = @"Select COUNT(*) from  dbo.Users where EmailID = @EmailID";
                SqlCommand cmd = new SqlCommand(query, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                con.Open();
                int count = (int)cmd.ExecuteScalar();
                return count > 0;
            }
        }



        // Isexist function to check the email exist in the database when user login
        public bool Isexist(UserLogin login)
        {
            using (SqlConnection con = new SqlConnection(cs))
            {
                string query = @"Select COUNT(*) from  dbo.Users where EmailID = @EmailID";
                SqlCommand cmd = new SqlCommand(query, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@EmailID", login.EmailID);
                con.Open();
                int count = (int)cmd.ExecuteScalar();
                return count > 0;
            }
        }



        //  write a function to check the mailId and password in valid or not
        public bool VerifyEmailPassword(string EmailID, string Password)
        {

            string PasswordHash = Password;//ConvertHashPassword(login.Password);
            using (SqlConnection con = new SqlConnection(cs))
            {
                string query = @"select count(*) from dbo.Users where EmailID = @EmailID and PasswordHash = @PasswordHash";
                SqlCommand cmd = new SqlCommand(query, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                cmd.Parameters.AddWithValue("@PasswordHash", PasswordHash);
                con.Open();

                int count = (int)cmd.ExecuteScalar();
                return count > 0;

            }
        }



        // write a function to add login 
        public void UpdateLoginTime(string EmailID)
        {
            using (SqlConnection con = new SqlConnection(cs))
            {
                string UpdateQuery = " UPDATE dbo.Users  SET LastLoginAt = @LastLoginAt WHERE EmailID = @EmailID";
                SqlCommand cmd = new SqlCommand(UpdateQuery, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                cmd.Parameters.AddWithValue("@LastLoginAt", DateTime.Now);
                con.Open();
                int id = (int)cmd.ExecuteNonQuery();
            }
            return;
        }



        // Write a function to Generate Random String for OTP And Password
        public string GenerateRandomString(int length = 10)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            char[] result = new char[length];

            for (int i = 0; i < length; i++)
                result[i] = chars[random.Next(chars.Length)];

            return new string(result);
        }



        // write a function to Convert the password into HashPassword
        public string ConvertHashPassword(string password)
        {
            using (SHA512 sha = SHA512.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(password);

                byte[] hashBytes = sha.ComputeHash(bytes);
                return Convert.ToBase64String(hashBytes);
            }
        }



        // write a function to change Password Force fully
        public string PassWordChange(string EmailID, string Password)
        {

            string PasswordHash = ConvertHashPassword(Password);
            using (SqlConnection con = new SqlConnection(cs))
            {
                string QUERY = "UPDATE dbo.Users SET PasswordHash = @PasswordHash,Status = @Status where EmailID = @EmailID";
                SqlCommand cmd = new SqlCommand(QUERY, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                cmd.Parameters.AddWithValue("@PasswordHash", PasswordHash);
                cmd.Parameters.AddWithValue("@Status", 1);

                con.Open();
                int id = cmd.ExecuteNonQuery();
            }
            return "PassWord Changed SuccessFully";
        }



        // write a functio to check the status of the user 
        public bool UserStatus(string EmailID)
        {
            using (SqlConnection con = new SqlConnection(cs))
            {
                string query = "Select Status from dbo.Users where EmailID = @EmailID";
                SqlCommand cmd = new SqlCommand(query, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@EmailID", EmailID);

                con.Open();
                SqlDataReader read = cmd.ExecuteReader();

                if (read.Read())
                {
                    int Status = Convert.ToInt32(read["status"]);
                    return Status == 1;
                }

            }
            return false;
        }


        // write a function to set the Status value afert SignUp and forgot password
        public void setStatus(string EmailID, int Status)
        {

            using (SqlConnection con = new SqlConnection(cs))
            {
                string query = "Update  Users set Status = @Status where EmailID = @EmailID";
                SqlCommand cmd = new SqlCommand(query, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                cmd.Parameters.AddWithValue("@Status", Status);
                con.Open();
                cmd.ExecuteNonQuery();

            }
            return;

        }


        // write a functio to verify Token 

        public DateTime VerifyUser(string token,string EmailID)
        {
            using (SqlConnection con = new SqlConnection(cs))
            {
                // Step 1: Get token generated time
                string checkQuery = "SELECT TokenGeneratedAt FROM Users WHERE token = @token AND EmailID = @EmailID";

                DateTime GeneratetokenTime;

                using (var cmd = new SqlCommand(checkQuery, con))
                {
                    cmd.Parameters.AddWithValue("@token", token);
                    cmd.Parameters.AddWithValue("@EmailID", EmailID);

                    con.Open();
                    object result = cmd.ExecuteScalar();
                    con.Close();

                    if (result == null)
                        return DateTime.MinValue; // Invalid token

                    GeneratetokenTime = Convert.ToDateTime(result);
                }

                // Step 2: Check expiry (30 minutes)
                if ((DateTime.Now - GeneratetokenTime).TotalMinutes > 30)
                {
                    return DateTime.MinValue; // Token expired
                }

                // Step 3: Verify user
                string updateQuery = "UPDATE Users SET IsUsedToken = 1, token = NULL, EmailVerified = 1 WHERE token = @token";

                using (var cmd = new SqlCommand(updateQuery, con))
                {
                    cmd.Parameters.AddWithValue("@token", token);

                    con.Open();
                    int rows = cmd.ExecuteNonQuery();
                    con.Close();

                    if (rows > 0)
                        return GeneratetokenTime; // Verified
                    else
                        return DateTime.MinValue; // Token mismatch (should not normally happen)
                }
            }
        }


        // write a funciton to generate the Token and link 

        public string UpdateToken(string EmailID)
        {
            string token = Guid.NewGuid().ToString();
            
            using (SqlConnection con = new SqlConnection(cs))
            {
                string UpdateToken = @"UPDATE Users SET token = @token,TokenGeneratedAt = @TokenGeneratedAt, IsUsedToken = 0 WHERE EmailID = @EmailID AND token IS NULL";
                SqlCommand cmd = new SqlCommand(UpdateToken, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@token", token);
                cmd.Parameters.AddWithValue("TokenGeneratedAt", DateTime.Now);
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                con.Open();
                cmd.ExecuteNonQuery ();
                return token;
              
            }

            return token;
        }

        // write a function to reset token 
        public bool resetToken(string EmailID)
        {
            using (SqlConnection con = new SqlConnection(cs))
            {
                string UpdateToken = @"UPDATE Users SET token = @token,TokenGeneratedAt = @TokenGeneratedAt, IsUsedToken = 0,EmailVerified=0 WHERE EmailID = @EmailID ";
                SqlCommand cmd = new SqlCommand(UpdateToken, con);
                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@token", DBNull.Value);
                cmd.Parameters.AddWithValue("@TokenGeneratedAt", DBNull.Value);
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                con.Open();
                int row = cmd.ExecuteNonQuery();
                return row>0;
            }           
        }
    }    
}
