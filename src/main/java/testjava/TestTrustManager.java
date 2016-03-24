package testjava;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.X509TrustManager;

import org.apache.commons.net.ftp.FTPSClient;

public class TestTrustManager {

    public static void main(String[] args) {
        System.out.println("TestJava");

        try {
                String certString = "-----BEGIN CERTIFICATE-----\n"
                                + "MIIDpTCCAo2gAwIBAgIJAJ1Zp1YkIlkMMA0GCSqGSIb3DQEBBQUAMGkxCzAJBgNV\n"
                                + "BAYTAlRXMQ8wDQYDVQQIDAZUQWl3YW4xDzANBgNVBAcMBlRhaXBlaTEQMA4GA1UE\n"
                                + "CgwHbHdoc3UnczEmMCQGA1UEAwwdRnJlZUJTRC1qZW5raW5zLm1icC5sd2hzdS5v\n"
                                + "cmcwHhcNMTUxMDI0MTU0NjE3WhcNMzUxMDE5MTU0NjE3WjBpMQswCQYDVQQGEwJU\n"
                                + "VzEPMA0GA1UECAwGVEFpd2FuMQ8wDQYDVQQHDAZUYWlwZWkxEDAOBgNVBAoMB2x3\n"
                                + "aHN1J3MxJjAkBgNVBAMMHUZyZWVCU0QtamVua2lucy5tYnAubHdoc3Uub3JnMIIB\n"
                                + "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyhsyI6jc8wuI9+9P0e0FXE36\n"
                                + "ibXkrUyE1PXwk1XTuDNBA/noqbB2xfkxB8IGxd81Mq1G5lLVw6q+c7bzSL7NcEPU\n"
                                + "/jPoaPq1cGExpMJgtCujNujbZY0/xwTWREtFBSVdrhxZqH7tYDa+SAA7NBjusV47\n"
                                + "Gx6MaE0wc8VdE4cHhf8AFuf7wo3hlISq4TfCPlhFi5ELHNhxyQ+AYJgKvHuw8gb7\n"
                                + "bE6pxBRpQBdC6c+pAGVMTxotkcobKcGllupkCg2Ef1vMdZvQprA4QpLzMfINrMMS\n"
                                + "swsoP/QEhv8Ke5tiXcIwXqhv37c7NSZBkVRa6uDxmdt0ppP81Y5FozgWM398DwID\n"
                                + "AQABo1AwTjAdBgNVHQ4EFgQU0Fw4G8/liLyM3IkJXEZmbcHJPtYwHwYDVR0jBBgw\n"
                                + "FoAU0Fw4G8/liLyM3IkJXEZmbcHJPtYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B\n"
                                + "AQUFAAOCAQEAPTtjGtw7wUN2iqXZZUUC6su01iJrmdXG/7ndETfm2UTQT9TQtLeE\n"
                                + "8ILpHcKTR9EEuXj31TEJbsVnN8khp9S0Bi+WQnxrSsnMTf8vzIMMfUt6V4xCNfdB\n"
                                + "FyCsSBhFd56dk6dRs+lQbOGK135k66PFnVpzL6ap3gibc2V6sTJi3A5fzPRG5AFn\n"
                                + "RBpMemIJ23s9sBNzoh3JzVRCkcKDjDm5RnWDEOwy4miU5mXX6xLP8IhQgpm5wtmq\n"
                                + "RCt5/M92mZirxiPzi5tt+4LExYc5X77rNkw2VM9R+FuOyriN+G1L1acYqwi2iuYW\n"
                                + "LtSjpjhgf+R4xVn24mLgTQYMeGAhmvck4A==\n" + "-----END CERTIFICATE-----";
                InputStream certStream = new ByteArrayInputStream(certString.getBytes());
                CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
                X509Certificate x509certificate = (X509Certificate) certificatefactory.generateCertificate(certStream);

                System.out.println("---Certificate---");
                System.out.println("type = " + x509certificate.getType());
                System.out.println("version = " + x509certificate.getVersion());
                System.out.println("subject = " + x509certificate.getSubjectDN().getName());
                System.out.println("valid from = " + x509certificate.getNotBefore());
                System.out.println("valid to = " + x509certificate.getNotAfter());
                System.out.println("serial number = " + x509certificate.getSerialNumber().toString(16));
                System.out.println("issuer = " + x509certificate.getIssuerDN().getName());
                System.out.println("signing algorithm = " + x509certificate.getSigAlgName());
                System.out.println("public key algorithm = " + x509certificate.getPublicKey().getAlgorithm());
                // Next, let's print out information about the extensions.
                System.out.println("---Extensions---");
                Set<String> setCritical = x509certificate.getCriticalExtensionOIDs();
                if (setCritical != null && setCritical.isEmpty() == false)
                  for (Iterator<String> iterator = setCritical.iterator(); iterator.hasNext(); )
                    System.out.println(iterator.next().toString() + " *critical*");
                Set<String> setNonCritical = x509certificate.getNonCriticalExtensionOIDs();
                if (setNonCritical != null && setNonCritical.isEmpty() == false)
                  for (Iterator<String> iterator = setNonCritical.iterator(); iterator.hasNext(); )
                    System.out.println(iterator.next().toString());
                // We're done.
                System.out.println("---");


                FTPSClient c = new FTPSClient(false);
                X509TrustManager xtm = new X509TrustManager() {

                    public X509Certificate[] getAcceptedIssuers() {
                        // TODO Auto-generated method stub
                        return null;
                    }

                    public void checkServerTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                        // TODO Auto-generated method stub

                    }

                    public void checkClientTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                        // TODO Auto-generated method stub

                    }
                };
                 c.setTrustManager(xtm);
        } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
        }

    }

}
