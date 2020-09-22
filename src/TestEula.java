import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import javax.crypto.Cipher;
import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Collections;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.TreeMap;

class TestEula {
    private static final String VERSION_MARKER = "Version: &nbsp;";

    public static void main(String[] args) {
        System.out.println("============= INIT SSL ===============");
        initSsl();
        System.out.println("============= LIST PROTOCOLS ===============");
        listProtocols();
        System.out.println("============= CHECK KEY LENGTH ================");
        checkKeyLength();
//        System.out.println("============= BOUNCY CONNECT ================");
//        bouncyConnect("https://safedoorpm-com.shoutcms.net/tos");
        System.out.println("============= GET EULA ================");
        getEula();
        System.out.println("============= GET EULA ENHANCED ================");
        getEulaEnhanced();
        System.out.println("============= DONE ================");
    }

    public static void bouncyConnect(String urlString) {
        try {
            java.security.SecureRandom secureRandom = new java.security.SecureRandom();
            URL url = new URL(urlString);
//            Socket socket = new Socket(java.net.InetAddress.getByName("safedoorpm-com.shoutcms.net"), 443);
            System.out.println("Get socket");
            Socket socket = new Socket(java.net.InetAddress.getByName(url.getHost()), 443);

            TlsClientProtocol protocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());
            DefaultTlsClient client = new DefaultTlsClient(new BcTlsCrypto(secureRandom)) {
                public TlsAuthentication getAuthentication() {
                    return new TlsAuthentication() {
                        // Capture the server certificate information!
                        public void notifyServerCertificate(TlsServerCertificate serverCertificate) {
                        }

                        public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                            return null;
                        }
                    };
                }
            };
            System.out.println("Connect");
            protocol.connect(client);

            System.out.println("Send request");
            java.io.OutputStream output = protocol.getOutputStream();
            //output.write(("GET /"+url.getFile()+" HTTP/1.1\r\n").getBytes(StandardCharsets.UTF_8));
            output.write(("GET /tos HTTP/1.1\r\n").getBytes(StandardCharsets.UTF_8));
            //output.write(("Host: "+url.getHost()+"\r\n").getBytes(StandardCharsets.UTF_8));
            output.write(("Host: safedoorpm-com.shoutcms.net:443\r\n").getBytes(StandardCharsets.UTF_8));
            output.write("Connection: close\r\n".getBytes(StandardCharsets.UTF_8)); // So the server will close socket immediately.
            output.write("\r\n".getBytes(StandardCharsets.UTF_8)); // HTTP1.1 requirement: last line must be empty line.
            output.flush();

            System.out.println("Get input/response");
            java.io.InputStream input = protocol.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            String line;
            while ((line = reader.readLine()) != null)
            {
                System.out.println(line);
            }
        } catch (IOException e) {
            System.out.println("IOException - failed to fetch eula: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("UNEXPECTED EXCEPTION - failed to fetch eula: " + e.getLocalizedMessage());
            e.printStackTrace();
        }

    }

    public static void initSsl() {
        try {
/*
            java.security.SecureRandom secureRandom = new java.security.SecureRandom();
            // KeyStore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreResrc.getInputStream(), keyStorePassword.toCharArray());
            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            keyMgrFact.init(keyStore, keyStorePassword.toCharArray());
*/
            // BouncyCastle providers
            if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
                int index = Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
                //int index = Security.addProvider(new BouncyCastleProvider());
                System.out.println("JSSE Security provider add index = " + index);
            } else {
                System.out.println("BC JSSE Provider already present");
            }

            //SSLContext context = SSLContext.getInstance("TLSv1.2",new BouncyCastleJsseProvider());
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                int index = Security.insertProviderAt(new BouncyCastleProvider(), 2);
                //int index = Security.addProvider(new BouncyCastleProvider());
                System.out.println("Security provider add index = " + index);
            } else {
                System.out.println("BC Provider already present");
            }
/*
            // TrustStore
            System.out.println("Creating trust store");
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
//            trustStore.load(trustStoreResrc.getInputStream(), trustStorePassword.toCharArray());
            System.out.println("Loading trust store");
            // get user password and file input stream
            String password = "Dog chow makes me very happy!";

            try (FileInputStream fis = new FileInputStream("/home/safedoorpm/.acme.sh/safedoorpm.com/safedoorpm.com.pfx") ) { // "/home/safedoorpm/safedoorpm_LE.p12");
                trustStore.load(fis, password.toCharArray());
            } finally {
            }
//            trustStore.load(null, null);
*/
            System.out.println("Get trust mgr factory");
            TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            System.out.println("Init factory");
            trustMgrFact.init((KeyStore) null);

/*
            System.out.println("Get key mgr factory");
            KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            System.out.println("Init factory");
            keyMgrFact.init(null);
*/

            SSLContext context = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
            //SSLContext context = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
            //context.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(), new java.security.SecureRandom());
            context.init(null, null, SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));
            //context.init(null, trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));
                // new java.security.SecureRandom());
            SSLContext.setDefault(context);
//        } catch (CertificateException e) {
//            System.out.println("Certificate exception: " + e.getLocalizedMessage());
//            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (KeyManagementException e) {
            System.out.println("KeyManagementException: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (KeyStoreException e) {
            System.out.println("KeyStoreException: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.out.println("NoSuchProviderException: " + e.getLocalizedMessage());
            e.printStackTrace();
//        } catch (InvalidAlgorithmParameterException e) {
//            System.out.println("InvalidAlgorithmParameterException: " + e.getLocalizedMessage());
//            e.printStackTrace();
//        } catch (IOException e) {
//            System.out.println("Generic IO exception: " + e.getLocalizedMessage());
//            e.printStackTrace();
        }
        //URL url = new URL("https://safedoorpm-com.shoutcms.net");
        //URLConnection connection = url.openConnection();
        //SSLServerSocketFactory sslSocketFactory = context.getSocketFactory();
        //connection.setSSLSocketFactory(sslSocketFactory);
    }

    public static void getEulaEnhanced() {
        try {
            final URL url = new URL("https://safedoorpm-com.shoutcms.net/tos");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            SSLContext context = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
            context.init(KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME).getKeyManagers(),
                    TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME).getTrustManagers(),
                    new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = context.getSocketFactory();
            conn.setSSLSocketFactory(sslSocketFactory);

            conn.setSSLSocketFactory(
                    new org.bouncycastle.jsse.util.CustomSSLSocketFactory(context.getSocketFactory())
                         {
                             @Override
                             protected Socket configureSocket(Socket s)
                             {
                                 if (s instanceof SSLSocket)
                                 {
                                     SSLSocket ssl = (SSLSocket)s;

                                     SNIHostName sniHostName = getSNIHostName(url);
                                     if (null != sniHostName)
                                     {
                                         SSLParameters sslParameters = new SSLParameters();

                                         sslParameters.setServerNames(Collections.<SNIServerName>
                                                 singletonList(sniHostName));
                                         ssl.setSSLParameters(sslParameters);
                                     }
                                 }
                                 return s;
                             }
                         });

            parseEulaFromUrl(url);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.out.println("NoSuchProviderException: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (KeyManagementException e) {
            System.out.println("KeyManagementException: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (MalformedURLException e) {
            System.out.println("MalformedURLException: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("IOException: " + e.getLocalizedMessage());
            e.printStackTrace();
        }

    }

    private static SNIHostName getSNIHostName(URL url)
    {
        String host = url.getHost();
        if (null != host && host.indexOf('.') > 0
                && !org.bouncycastle.util.IPAddress.isValid(host))
        {
            try
            {
                return new SNIHostName(host);
            }
            catch (RuntimeException e)
            {
            }
        }
        return null;
    }

    public static void getEula() {
        try {
            URL url = new URL("https://safedoorpm-com.shoutcms.net/tos");

            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            SSLContext context = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
            context.init(null, null, new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = context.getSocketFactory();
            connection.setSSLSocketFactory(sslSocketFactory);

            parseEulaFromUrl(url);

//        } catch (MalformedURLException e) {
//            System.out.println("Malformed URL: " +  e.getLocalizedMessage());
//            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            System.out.println("no such provider exception: " +  e.getLocalizedMessage());
            e.printStackTrace();
        } catch (KeyManagementException e) {
            System.out.println("key management exception: " +  e.getLocalizedMessage());
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("No such alg exception: " +  e.getLocalizedMessage());
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("Generic I/O error: " +  e.getLocalizedMessage());
            e.printStackTrace();
        }

    }

    private static void parseEulaFromUrl(URL url) {
        try (InputStream in = url.openStream()) {
            System.out.println("Stream open");
            String eulaContent = new Scanner(in, "UTF-8").useDelimiter("\\A").next();

            // mine out the version number
            int markerStartPosition = eulaContent.indexOf(VERSION_MARKER);
            System.out.println("EULA Version marker start position " + markerStartPosition + ".");
            if (markerStartPosition >= 0) {
                System.out.println("Parsing EULA Version.");
                String versionString = eulaContent.substring(markerStartPosition+VERSION_MARKER.length());
                int versionEnd = versionString.indexOf('\n');
                if (versionEnd >= 0) {
                    System.out.println(versionString.substring(0,versionEnd));
                } else {
                    System.out.println("No EOL");
                }

            } else {
                System.out.println("EULA Version marker not found.");
            }
        } catch (IOException e) {
            System.out.println("failed to fetch eula: " + e.getLocalizedMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("UNEXPECTED EXCEPTION - failed to fetch eula: " + e.getLocalizedMessage());
            e.printStackTrace();
        }
    }

    public static void listProtocols() {
        SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

        TreeMap<String, Boolean> ciphers = new TreeMap<>();
        for (String cipher : ssf.getSupportedCipherSuites()) {
            ciphers.put(cipher, Boolean.FALSE);
        }
        for (String cipher : ssf.getDefaultCipherSuites()) {
            ciphers.put(cipher, Boolean.TRUE);
        }

        System.out.println("Default Cipher");
        for (Entry<String, Boolean> cipher : ciphers.entrySet()) {
            System.out.printf("   %-5s%s%n", (cipher.getValue() ? '*' : ' '), cipher.getKey());
        }

    }

    public static void checkKeyLength() {
        int allowedKeyLength = 0;
        try {
          allowedKeyLength = Cipher.getMaxAllowedKeyLength("AES");
        } catch (NoSuchAlgorithmException e) {
          e.printStackTrace();
        }
        System.out.println("The allowed key length for AES is: " + allowedKeyLength);
    }

}
