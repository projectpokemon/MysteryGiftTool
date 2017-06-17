using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace MysteryGiftTool
{
    public static class NetworkUtils
    {
        public static byte[] TryDownload(string file)
        {
            try
            {
                return new WebClient().DownloadData(file);
            }
            catch (WebException)
            {
                Console.WriteLine($"Failed to download {file}.");
                return null;
            }
        }

        public static async Task<string> MakeCertifiedRequest(string URL, byte[] clCertA, string clCertAPassword, bool json = false)
        {
            var ClCertA = new X509Certificate2(clCertA, clCertAPassword);
            var wr = WebRequest.Create(new Uri(URL)) as HttpWebRequest;
            wr.UserAgent = $"CTR NUP 040600 {DateTime.Now.ToString("MMMM dd yyyy HH:mm:ss")}";
            wr.KeepAlive = true;
            if (json)
                wr.Accept = "application/json";
            wr.Method = WebRequestMethods.Http.Get;
            wr.ClientCertificates.Clear();
            wr.ClientCertificates.Add(ClCertA);
            string response;
            try
            {
                using (var resp = await wr.GetResponseAsync() as HttpWebResponse)
                {
                    response = new StreamReader(resp.GetResponseStream()).ReadToEnd();
                }
            }
            catch (WebException ex)
            {
                Console.WriteLine("Web exception: " + ex.ToString());
                Console.WriteLine("Target URL: " + URL);
                response = new StreamReader(ex.Response.GetResponseStream()).ReadToEnd();
            }
            return response;
        }

    }
}