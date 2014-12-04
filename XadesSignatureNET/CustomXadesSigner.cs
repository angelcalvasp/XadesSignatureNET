using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using es.mityc.firmaJava.libreria.xades;
using java.io;
using java.lang;
using java.security;
using java.security.cert;
using java.util;
using javax.xml.parsers;
using javax.xml.transform;
using javax.xml.transform.dom;
using javax.xml.transform.stream;
using org.apache.regexp;
using org.apache.xalan.processor;
using org.w3c.dom;
using org.xml.sax;
using Exception = System.Exception;
using File = java.io.File;
using IOException = java.io.IOException;
using Object = System.Object;
using String = System.String;
using StringReader = java.io.StringReader;
using StringWriter = java.io.StringWriter;

namespace XadesSignatureNET
{
    public class CustomXadesSigner
    {





        public string Sign(DataToSign dataToSign, string certificatePath, string certificatePass)
        {
            KeyStore keyStore = getKeyStore(certificatePath, certificatePass);

            if (keyStore == null)
            {
                throw new Exception("No se pudo obtener almacen de firma.");
            }

            String alias = getAlias(keyStore);

            X509Certificate certificate = null;

            try
            {
                certificate = (X509Certificate)keyStore.getCertificate(alias);
                if (certificate == null)
                {
                    throw new Exception("No existe ningún certificado para firmar.");
                }
            }
            catch (KeyStoreException ex)
            {
                throw new Exception(ex.Message);
            }


            PrivateKey privateKey = null;
            KeyStore tmpKs = keyStore;
            try
            {
                privateKey = (PrivateKey) tmpKs.getKey(alias, certificatePass.ToCharArray());
            }
            catch (UnrecoverableKeyException e)
            {
                throw new Exception("No existe clave privada para firmar.");
            }
            catch (KeyStoreException e)
            {
                throw new Exception("No existe clave privada para firmar.");
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new Exception("No existe clave privada para firmar.");
            }
            catch (Exception ex)
            {
                throw ex;
            }

            Provider provider = keyStore.getProvider();

            FirmaXML firma = new FirmaXML();

            Document docSigned = null;
            try
            {
                Object[] res = firma.signFile(certificate, dataToSign, privateKey, provider);
                docSigned = (Document)res[0];
            }
            catch (Exception ex)
            {
                throw new Exception("Error realizando la firma");
            }


            if (Validar(docSigned))
            {

                SaveDocumenteDisk(docSigned, "C:\\Temp\\output.xml");

                var stringXml = GetStringFromDoc(docSigned);

                return stringXml;

                /*

                var result = new XmlDocument();
                result.PreserveWhitespace = true;

                var sr = new System.IO.StringReader(stringXml);


                XDocument xDocument = XDocument.Load(sr, LoadOptions.PreserveWhitespace);

                var temp = xDocument.ToString(SaveOptions.DisableFormatting);
                */
                /*
                var sr = new System.IO.StringReader(stringXml);

                var signedXml = new SignedXml();
                signedXml.LoadXml();

                var result = new XmlDocument();
                    result.PreserveWhitespace = true;
                    result.Load(sr);
                
                sr.Dispose();
                */

                //result.LoadXml(stringXml);
                //return result;
            }
            else
            {
                throw new Exception("Error el archivo no paso la prueba de verificacion");
            }

            return null;
        }

        protected Document GetDocument(String resource)
        {
            Document doc = null;
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            File file = new File(resource);
            try
            {
                DocumentBuilder db = dbf.newDocumentBuilder();

                doc = db.parse(file);
            }
            catch (ParserConfigurationException ex)
            {
                //System.err.println("Error al parsear el documento");
                ex.printStackTrace();
                //System.exit(-1);
            }
            catch (SAXException ex)
            {
                //System.err.println("Error al parsear el documento");
                ex.printStackTrace();
                // System.exit(-1);
            }
            catch (IOException ex)
            {
                //System.err.println("Error al parsear el documento");
                ex.printStackTrace();
                //System.exit(-1);
            }
            catch (IllegalArgumentException ex)
            {
                //System.err.println("Error al parsear el documento");
                ex.printStackTrace();
                //System.exit(-1);
            }
            return doc;
        }

        private KeyStore getKeyStore(byte[] certificateBytes, string password)
        {
            KeyStore ks = null;
            try
            {

                ks = KeyStore.getInstance("PKCS12");
                var inputStream = new ByteArrayInputStream(certificateBytes);
                ks.load(inputStream, password.ToCharArray());

                /*
                ks = KeyStore.getInstance("PKCS12");
                ks.load(new FileInputStream(certificatePath), certificatePass.ToCharArray());
                */
            }
            catch (KeyStoreException e)
            {
                e.printStackTrace();
            }
            catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }
            catch (CertificateException e)
            {
                e.printStackTrace();
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            return ks;
        }

        private KeyStore getKeyStore(string certificatePath, string certificatePass)
        {
            KeyStore ks = null;
            try
            {
                ks = KeyStore.getInstance("PKCS12");
                ks.load(new FileInputStream(certificatePath), certificatePass.ToCharArray());
            }
            catch (KeyStoreException e)
            {
                e.printStackTrace();
            }
            catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }
            catch (CertificateException e)
            {
                e.printStackTrace();
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            return ks;
        }



        private String getAlias(KeyStore keyStore)
        {
            String alias = null;
            Enumeration nombres;
            try
            {
                nombres = keyStore.aliases();

                while (nombres.hasMoreElements())
                {
                    String tmpAlias = (String)nombres.nextElement();
                    if (keyStore.isKeyEntry(tmpAlias))
                        alias = tmpAlias;
                }
            }
            catch (KeyStoreException e)
            {
                e.printStackTrace();
            }
            return alias;
        }

        public void SaveDocumenteDisk(Document document, String pathXml)
        {
            try
            {

                DOMSource source = new DOMSource(document);
                StreamResult result = new StreamResult(new File(pathXml));
                TransformerFactory transformerFactory = new TransformerFactoryImpl();
                Transformer transformer;
                transformer = transformerFactory.newTransformer();
                transformer.transform(source, result);
            }
            catch (TransformerConfigurationException e)
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            catch (TransformerException e)
            {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        public bool Validar(Document doc)
        {
            bool esValido = true;


            ArrayList results = null;


            if (doc != null)
            {
                try
                {
                    ValidarFirmaXML vXml = new ValidarFirmaXML();
                    results = vXml.validar(doc, "./", null);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e);
                }
                ResultadoValidacion result = null;
                var it = results.iterator();
                while (it.hasNext())
                {
                    result = (ResultadoValidacion)it.next();
                    esValido = result.isValidate();
                    if (esValido)
                    {
                        Debug.WriteLine("La firma es valida = " + result.getNivelValido() + "\nFirmado el: " + result.getDatosFirma().getFechaFirma());
                    }
                    else
                    {
                        Debug.WriteLine("La firma NO es valida\n" + result.getLog());
                    }
                }
            }
            return esValido;
        }

        public static String GetStringFromDoc(Document doc)
        {
            try
            {
                StringWriter sw = new StringWriter();
                TransformerFactory tf = new TransformerFactoryImpl();
                Transformer transformer = tf.newTransformer();
                transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
                transformer.setOutputProperty(OutputKeys.METHOD, "xml");
                transformer.setOutputProperty(OutputKeys.INDENT, "no");
                transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
                transformer.transform(new DOMSource(doc), new StreamResult(sw));
                return sw.toString();
            }
            catch (Exception ex)
            {
                throw new RuntimeException("Error converting to String", ex);
            }
        }

        public static void ElementToStream(Element element, OutputStream outputStream)
        {
            try
            {
                DOMSource source = new DOMSource(element);
                StreamResult result = new StreamResult(outputStream);
                TransformerFactory transFactory = TransformerFactory.newInstance();
                Transformer transformer = transFactory.newTransformer();
                transformer.transform(source, result);
            }
            catch (Exception ex)
            {
            }
        }

        public static String DocumentToString(Document doc)
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ElementToStream(doc.getDocumentElement(), baos);

            var result = System.Text.Encoding.UTF8.GetString(baos.toByteArray());
            return result;
        }

    }
}
