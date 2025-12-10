using Humanizer.Localisation.DateToOrdinalWords;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using NuGet.Protocol;
using MARS.Models.Account;
using MARS.Models.Accounts;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Net.Security;

namespace MARS.DataAccess
{
    public class DataAccessLayer
    {
        public string cs = StringConnection.dbcs;

        // write a functio SignUp for registration afeter verification 
        public string Signup(string EmailID, string MobileNo, string FirstName, string LastName,string token)
        {
           
            using (SqlConnection con = new SqlConnection(cs))
            {
                string query = "INSERT INTO dbo.Users (MobileNo, EmailID, EmailVerified,MobileVerified,FirstName,LastName,Status,token,TokenGeneratedAt,IsUsedToken) VALUES (@MobileNo, @EmailID,@EmailVerified,@MobileVerified,@FirstName,@LastName,@Status,@token,@TokenGeneratedAt,@IsUsedToken)";
                SqlCommand cmd = new SqlCommand(query, con);

                cmd.CommandType = CommandType.Text;
                cmd.Parameters.AddWithValue("@FirstName", FirstName);
                cmd.Parameters.AddWithValue("@LastName", LastName);
                cmd.Parameters.AddWithValue("@MobileNo", MobileNo);
                cmd.Parameters.AddWithValue("@EmailID", EmailID);
                cmd.Parameters.AddWithValue("@EmailVerified", 0);
                cmd.Parameters.AddWithValue("@MobileVerified", 0);              
                cmd.Parameters.AddWithValue("@Status", 0);
                cmd.Parameters.AddWithValue("@TokenGeneratedAt", DateTime.UtcNow);
                cmd.Parameters.AddWithValue("@token", token);
                cmd.Parameters.AddWithValue("@IsUsedToken", 0);
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

        public bool VerifyUser(string token)
        {
            using (SqlConnection con = new SqlConnection(cs))
            {
                string checkQuery = "SELECT COUNT(*) FROM Users WHERE token = @token AND IsUsedToken = 0";
                using (var cmd = new SqlCommand(checkQuery, con))
                {
                    cmd.Parameters.AddWithValue("@token", token);
                    con.Open();
                    int count = (int)cmd.ExecuteScalar();

                    if (count == 0)
                        return false; // Token invalid or already verified
                }

                // Update user as verified
                string updateQuery = "UPDATE Users SET IsUsedToken = 1, token = NULL WHERE token = @Token";
                using (var cmd = new SqlCommand(updateQuery, con))
                {
                    cmd.Parameters.AddWithValue("@token", token);
                    
                    int rows = cmd.ExecuteNonQuery();
                    return rows > 0;
                }
            }
        }



    }
}
