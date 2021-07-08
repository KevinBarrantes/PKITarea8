using System;
using System.IO;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Math;
using System.Security.Cryptography;
using System.Text;

namespace DigitalSign
{
    class Program
    {
        static void Main(string[] args)
        {
            //Ruta del PFX para obtener la llave privada y el certificado
            string KEYSTORE = "C:\\Users\\Kevin\\Documents\\Otros\\2021ISemestre\\PKI\\Tarea8\\ArchivosCertificado\\kevinPFX.pfx";
            bool active = true;


            while (active) {
                System.Console.Write("Servicios de PKI\n" +
                    "1. Autenticación mediante certificado\n" +
                    "2. Firma de PDF\n" + 
                    "3. Estampa de tiempo de SINPE\n" +
                    "4. Cerrar aplicación\n" +
                    "Elija una de las opciones anteriores: ");
                int option = Int32.Parse(Console.ReadLine());

                switch (option) {
                    
                    //Opción de autenticación
                    case 1:
                        bool authenticated = false;                        

                        while (!authenticated)
                        {
                            authenticated = Authenticate(KEYSTORE, "1234");
                        }

                        break;

                    //Opción de firma de pdf
                    case 2:
                        Sign(KEYSTORE);
                        break;

                    //Opción de timestamp de Sinpe
                    case 3:
                        Timestamp();
                        break;

                    //Cerrar programa
                    case 4:
                        active = false;
                        break;

                    default:
                        break;


                }

                //Limpiar la consola
                System.Console.Clear();


            }


           

           


        }



        //Código adaptado de https://docs.microsoft.com/en-us/aspnet/core/security/authentication/certauth?view=aspnetcore-5.0
        //Autenticación del usuario mediante certificado
        private static bool Authenticate(string keystore, string password)
        {
            //Se lee el certificado base mediante el pfx
            var cert = new X509Certificate2(System.IO.Path.Combine(keystore), password);

            //Se recibe el certificado con el que el usuario se autentica
            System.Console.Write("\nEscriba la ruta de su certificado: ");
            string testString = Console.ReadLine();  

            //Lectura del certificado
            byte[] rawData = ReadCertificate(testString);

            //Carga del certificado
            X509Certificate2 clientCertificate = new X509Certificate2(rawData);      
            
            //Comparación del Thumbprint
            if (clientCertificate.Thumbprint == cert.Thumbprint)
            {
                System.Console.Write("\nInicio de sesión exitoso");
                System.Console.Write("\nInformación del certificado para autorizar\n" + clientCertificate.Subject);
                System.Console.Write("\nInformación del certificado brindado por el cliente\n" + clientCertificate.Subject);
                System.Console.Write("\nPresione Enter para volver al menú");
                System.Console.ReadLine();
                return true;
            }

            System.Console.Write("\nNo se pudo autenticar su identidad mediante el certificado brindado");
            System.Console.Write("\nPresione Enter para volver al menú");
            System.Console.ReadLine();

            return false;
        }

        static byte[] ReadCertificate(string certificate)
        {
            FileStream fileStream = new FileStream(certificate, FileMode.Open, FileAccess.Read);
            int length = (int)fileStream.Length;
            byte[] certBytes = new byte[length];
            fileStream.Read(certBytes, 0, length);
            fileStream.Close();
            return certBytes;
        }


        //Ejemplo adaptado de https://viewbag.wordpress.com/2019/12/24/pdf-digital-signatures-itext7-bouncy-castle-net-core/
        private static void Sign(string KEYSTORE) {
            char[] PASSWORD = "1234".ToCharArray();
            Pkcs12Store pk12 = new Pkcs12Store(new FileStream(KEYSTORE,
           FileMode.Open, FileAccess.Read), PASSWORD);
            string alias = null;
            foreach (object a in pk12.Aliases)
            {
                alias = ((string)a);
                if (pk12.IsKeyEntry(alias))
                {
                    break;
                }
            }
            ICipherParameters pk = pk12.GetKey(alias).Key;
            X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
            Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[ce.Length];
            for (int k = 0; k < ce.Length; ++k)
            {
                chain[k] = ce[k].Certificate;
            }

            string DEST = "C:\\Users\\Kevin\\Documents\\Otros\\2021ISemestre\\PKI\\Tarea8\\ArchivosCertificado\\Tarea6FirmadoPKCS7B70998.pdf";
            string SRC = "C:\\Users\\Kevin\\Documents\\Otros\\2021ISemestre\\PKI\\Tarea8\\ArchivosCertificado\\Tarea6PKCS7B70998.pdf";

            PdfReader reader = new PdfReader(SRC);
            PdfSigner signer = new PdfSigner(reader,
            new FileStream(DEST, FileMode.Create),
            new StampingProperties());
            signer.SetFieldName("CampoTarea");

            PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
            appearance.SetReason("Tarea 8 de PKI")
                .SetLocation("Alajuela")
                .SetPageRect(new Rectangle(0, 0, 200, 100))
                .SetPageNumber(1);            
            IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256);
            signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
            System.Console.Write("\nFirma del documento exitosa\nPresione Enter para volver al menú");
            System.Console.ReadLine();
        }


        //Adaptado del ejemplo 5 de https://csharp.hotexamples.com/es/examples/Org.BouncyCastle.Tsp/TimeStampResponse/-/php-timestampresponse-class-examples.html
        // y de https://www.digistamp.com/toolkitDoc/comNetToolkit/index.htm
        private static void Timestamp() {
            var data = "Mensaje a estampar";
            SHA256 sha256 = SHA256CryptoServiceProvider.Create();
            byte[] hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(data));
            TimeStampRequestGenerator tsrq = new TimeStampRequestGenerator();
            tsrq.SetCertReq(true);
            TimeStampRequest tsr = tsrq.Generate(TspAlgorithms.Sha256, hash, BigInteger.ValueOf(100));
            byte[] encodedRequest = tsr.GetEncoded();


            //Algoritmo a usar (SHA-256) y dirección de TSA obtenidas de https://www.sugeval.fi.cr/serviciosytramites/ServiciosMensajeriaDocumentos/Xolido%20Sign%20hash%20conf.pdf
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://tsa.sinpe.fi.cr/tsahttp");
            req.Method = "POST";
            req.ContentType = "application/timestamp-query";
            req.ContentLength = encodedRequest.Length;

            Stream reqStream = req.GetRequestStream();
            reqStream.Write(encodedRequest, 0, encodedRequest.Length);
            reqStream.Close();

            HttpWebResponse res = (HttpWebResponse)req.GetResponse();
            if (res == null)
            {
                Console.WriteLine("Unsuccesfull response");                
            }
            else
            {
                Console.WriteLine(res.ResponseUri);
                Console.WriteLine(res.Headers);                
                Stream resStream = new BufferedStream(res.GetResponseStream());
                TimeStampResponse tsRes = new TimeStampResponse(resStream);
                Console.WriteLine("Estado del timestamp" + res.StatusDescription);
                Console.WriteLine("Servidor" + res.Server);
                resStream.Close();
                Console.WriteLine(tsRes.GetStatusString());                


                //return tsRes.TimeStampToken.GetEncoded();
            }

            System.Console.Write("\nPresione Enter para volver al menú");
            System.Console.ReadLine();
        }


        //C:\Users\Kevin\Documents\Otros\2021ISemestre\PKI\Tarea8\ArchivosCertificado\kevin.cer
    }
}
