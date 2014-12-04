using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using com.sun.org.apache.xerces.@internal.jaxp;
using es.mityc.firmaJava.libreria.xades;
using es.mityc.javasign.xml.refs;
using java.io;
using javax.xml.parsers;
using org.apache.bcel.generic;
using org.w3c.dom;
using org.xml.sax;

namespace XadesSignatureNET
{
    public class Xades132Signer
    {

        public string SignDocument(string xmlString, string certificatePath, string certificatePassword)
        {

            var signature = new CustomXadesSigner();

            var dataToSign = createDataToSign(xmlString);

            try
            {
                var signedXml = signature.Sign(dataToSign, certificatePath, certificatePassword);
                return signedXml;
            }
            catch (Exception ex)
            {
                return null;
            }


        }

        public string SignDocument(XmlDocument document, string certificatePath, string certificatePassword)
        {

            var signature = new CustomXadesSigner();

            var dataToSign = createDataToSign(document.OuterXml);

            try
            {
                var signedXml = signature.Sign(dataToSign, certificatePath, certificatePassword);
                return signedXml;
            }
            catch (Exception ex)
            {
                return null;
            }


        }

        public string signDocument(XmlDocument document, X509Certificate2 certificate,string password)
        {

            //GetCertificateBytes
            byte[] certBytes = certificate.Export(X509ContentType.Pkcs12);

            var xmlContent = document.OuterXml;


            CustomXadesSigner signature = new CustomXadesSigner();

            return "";

        }

        private DataToSign createDataToSign(string xmlContent)
        {

            DataToSign datosAFirmar = new DataToSign();

            datosAFirmar.setXadesFormat(EnumFormatoFirma.XAdES_BES);

            datosAFirmar.setEsquema(XAdESSchemas.XAdES_132);
            datosAFirmar.setXMLEncoding("UTF-8");
            datosAFirmar.setEnveloped(true);
            datosAFirmar.addObject(new ObjectToSign(new InternObjectToSign("comprobante"), "contenido comprobante", null, "text/xml", null));
            datosAFirmar.setParentSignNode("comprobante");

            //DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilderFactory dbf = new DocumentBuilderFactoryImpl();
            dbf.setNamespaceAware(true);
            DocumentBuilder builder;
            builder = dbf.newDocumentBuilder();

            Document document = builder.parse(new InputSource(new StringReader(xmlContent)));
            datosAFirmar.setDocument(document);

            return datosAFirmar;
        }

    }
}
