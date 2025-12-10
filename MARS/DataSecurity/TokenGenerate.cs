using System.Security.Cryptography;
namespace MARS.DataSecurity
{
    public class TokenGenerate
    {
        public string GenerateToken()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var bytes = new byte[32];
                rng.GetBytes(bytes);
                return Convert.ToBase64String(bytes);
            }
        }
    }
}
