import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.util.CustomSSLSocketFactory;

import javax.crypto.Cipher;
import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.TreeMap;

class TestEula {
    private static final String VERSION_MARKER = "Version: &nbsp;";
    private static TrustManagerFactory trustMgrFact;
    private static KeyManagerFactory keyMgrFact;

    public static void main(String[] args) {
        System.out.println("============= INIT SSL ===============");
        initSsl();
        System.out.println("============= LIST PROTOCOLS ===============");
        listProtocols();
        System.out.println("============= CHECK KEY LENGTH ================");
        checkKeyLength();
        System.out.println("============= GET EULA ================");
        getEula();
        System.out.println("============= GET EULA ENHANCED ================");
        getEulaEnhanced();
        System.out.println("============= DONE ================");
    }

    public static void initSsl() {
        try {
            // BouncyCastle providers
            if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
                int index = Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
                //int index = Security.addProvider(new BouncyCastleProvider());
                System.out.println("JSSE Security provider add index = " + index);
            } else {
                System.out.println("BC JSSE Provider already present");
            }

            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                int index = Security.insertProviderAt(new BouncyCastleProvider(), 2);
                //int index = Security.addProvider(new BouncyCastleProvider());
                System.out.println("Security provider add index = " + index);
            } else {
                System.out.println("BC Provider already present");
            }

            // Trust manager factory
            System.out.println("Get trust mgr factory");
            trustMgrFact = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            System.out.println("Init trust mgr factory");
            trustMgrFact.init((KeyStore) null);

            // Key manager factory
            System.out.println("Get default key store");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            System.out.println("Get key mgr factory");
            keyMgrFact = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);
            System.out.println("Init key mgr factory");
            keyMgrFact.init(ks, "".toCharArray());

            SSLContext context = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
            context.init(null, null, SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));
            SSLContext.setDefault(context);
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchProviderException | KeyManagementException | NoSuchAlgorithmException | IOException | CertificateException e) {
            System.out.println(e.getLocalizedMessage());
            e.printStackTrace();
        }
    }

    public static void getEulaEnhanced() {
        try {
            //final URL url = new URL("https://safedoorpm-com.shoutcms.net/tos");
            final URL url = new URL("https://google.com");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            SSLContext context = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
            final TrustManager[] trustManagers = trustMgrFact.getTrustManagers();
            final KeyManager[] keyManagers = keyMgrFact.getKeyManagers();
            context.init(keyManagers, trustManagers, new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = context.getSocketFactory();
            conn.setSSLSocketFactory(sslSocketFactory);

            System.out.println("Create SSL Socket Factory");
            conn.setSSLSocketFactory(
                    new CustomSSLSocketFactory(context.getSocketFactory())
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

            System.out.println("Parse EULA from URL");
            parseEulaFromUrl(url);
        } catch (IllegalStateException | IOException | KeyManagementException | NoSuchProviderException | NoSuchAlgorithmException e) {
            System.out.println(e.getLocalizedMessage());
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
            //final URL url = new URL("https://safedoorpm-com.shoutcms.net/tos");
            final URL url = new URL("https://google.com");

            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            SSLContext context = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
            context.init(null, null, new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = context.getSocketFactory();
            connection.setSSLSocketFactory(sslSocketFactory);

            parseEulaFromUrl(url);

        } catch (IOException | NoSuchAlgorithmException | KeyManagementException | NoSuchProviderException e) {
            System.out.println(e.getLocalizedMessage());
            e.printStackTrace();
        }

    }

    private static void parseEulaFromUrl(URL url) {
        System.out.println("Reading from URL '" + url.toString() + "'.");
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
        } catch (Exception e) {
            System.out.println(e.getLocalizedMessage());
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
