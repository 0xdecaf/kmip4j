package ch.ntb.inf.kmip.stub.transport;
/**
 * KMIPStubTransportLayerHTTPSLocalHost.java
 * -----------------------------------------------------------------
 *     __ __ __  ___________ 
 *    / //_//  |/  /  _/ __ \	  .--.
 *   / ,<  / /|_/ // // /_/ /	 /.-. '----------.
 *  / /| |/ /  / // // ____/ 	 \'-' .--"--""-"-'
 * /_/ |_/_/  /_/___/_/      	  '--'
 * 
 * -----------------------------------------------------------------
 * Description:
 * The KMIPStubTransportLayerHTTPSLocalHost provides the 
 * communication between a server and a client via HTTPS, using a 
 * HttpsUrlConnection, where the server and the client both are 
 * running on the local host.
 *
 * @author     Stefanie Meile <stefaniemeile@gmail.com>
 * @author     Michael Guster <michael.guster@gmail.com>
 * @org.       NTB - University of Applied Sciences Buchs, (CH)
 * @copyright  Copyright ï¿½ 2013, Stefanie Meile, Michael Guster
 * @license    Simplified BSD License (see LICENSE.TXT)
 * @version    1.0, 2013/08/09
 * @since      Class available since Release 1.0
 *
 * 
 */

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.ntb.inf.kmip.utils.KMIPUtils;

/**
 * The KMIPStubTransportLayerHTTPSLocalHost provides the communication between a server and a client via HTTPS,
 * using a HttpsUrlConnection, where the server and the client both are running on the local host. 
 */
public class KMIPStubTransportLayerHTTPSLocalHost implements KMIPStubTransportLayerInterface{

	private static final Logger logger = LoggerFactory.getLogger(KMIPStubTransportLayerHTTPSLocalHost.class);

	private String url;
	private String keyStoreFileName;
	private String keyStorePassword;
	private String alias = null;

	private String trustStoreFileName;
	private String trustStorePassword;

	static {
	    // for localhost testing only
	    javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
	    new javax.net.ssl.HostnameVerifier(){
 	        public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) {
				return hostname.equals("localhost");
			}
	    });
	}
	

	
	public KMIPStubTransportLayerHTTPSLocalHost() {
		logger.info("KMIPStubTransportLayerHTTPS initialized...");
	}
    
    public ArrayList<Byte> send(ArrayList<Byte> al){
    	String kmipRequest = KMIPUtils.convertArrayListToHexString(al);
    	try {
    		// prepare Post-Parameter-String
    		String parameter = "KMIPRequest="+URLEncoder.encode(kmipRequest,"UTF-8");	
            // create key and trust managers
            KeyManager[] keyManagers = createKeyManagers(keyStoreFileName, keyStorePassword, alias);
            TrustManager[] trustManagers = createTrustManagers(trustStoreFileName, trustStorePassword);
            // init context with managers data   
            SSLSocketFactory factory = initItAll(keyManagers, trustManagers);
            // execute Post
            String responseString = executePost(url, parameter, factory);
            return KMIPUtils.convertHexStringToArrayList(responseString);
        } catch (Exception e) {
			throw new RuntimeException("Exception sending request to " + url, e);
        }
    }
 
    private static String executePost(String targetURL, String urlParameters, SSLSocketFactory sslSocketFactory)
			throws IOException {
        URL url = new URL(targetURL);
        URLConnection connection = url.openConnection();
        HttpsURLConnection httpsConnection = null;
        if (connection instanceof HttpsURLConnection) {
        	httpsConnection = (HttpsURLConnection) connection;
        }
        else{
        	logger.warn("Connection is no HttpsURLConnection!");
        }

        try{
        	httpsConnection.setSSLSocketFactory(sslSocketFactory);
        	httpsConnection.setRequestMethod("POST");
        	httpsConnection.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
        	httpsConnection.setRequestProperty("Content-Length","" + Integer.toString(urlParameters.getBytes().length));
        	httpsConnection.setRequestProperty("Content-Language", "en-US");
        	httpsConnection.setRequestProperty("Cache-Control","no-cache");
        	httpsConnection.setUseCaches(false);
        	httpsConnection.setDoInput(true);
        	httpsConnection.setDoOutput(true); 
        
			// Send request
			DataOutputStream wr = new DataOutputStream(httpsConnection.getOutputStream());
			wr.writeBytes(urlParameters);
		
			wr.flush();
			wr.close(); 
			
			// Get Response
			InputStream is = httpsConnection.getInputStream();
			BufferedReader rd = new BufferedReader(new InputStreamReader(is));
			String line;
			StringBuilder response = new StringBuilder();
			while ((line = rd.readLine()) != null) {
				response.append(line);
				response.append('\r');
			}
			rd.close();
	
			return response.toString();
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			if (httpsConnection != null) {
				httpsConnection.disconnect();
			}
		}
    }
 
    private static SSLSocketFactory initItAll(KeyManager[] keyManagers, TrustManager[] trustManagers)
        	throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(keyManagers, trustManagers, null);
        return context.getSocketFactory();
    }
 
    private static KeyManager[] createKeyManagers(String keyStoreFileName, String keyStorePassword, String alias)
        	throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        //create Inputstream to keystore file
        java.io.InputStream inputStream = new java.io.FileInputStream(keyStoreFileName);
        //create keystore object, load it with keystorefile data
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(inputStream, keyStorePassword == null ? null : keyStorePassword.toCharArray());
 
        KeyManager[] managers;
        if (alias != null) {
        	managers = new KeyManager[] {new AliasKeyManager(keyStore, alias, keyStorePassword)};
        } else {
            //create keymanager factory and load the keystore object in it 
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, keyStorePassword == null ? null : keyStorePassword.toCharArray());
            managers = keyManagerFactory.getKeyManagers();
        }
        //return 
        return managers;
    }
 
    private static TrustManager[] createTrustManagers(String trustStoreFileName, String trustStorePassword)
        throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        //create Inputstream to truststore file
        java.io.InputStream inputStream = new java.io.FileInputStream(trustStoreFileName);
        //create keystore object, load it with truststorefile data
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(inputStream, trustStorePassword == null ? null : trustStorePassword.toCharArray());

        //create trustmanager factory and load the keystore object in it 
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        //return 
        return trustManagerFactory.getTrustManagers();
    }
 
//    private static void printKeystoreInfo(KeyStore keystore) throws KeyStoreException {
//        System.out.println("Provider : " + keystore.getProvider().getName());
//        System.out.println("Type : " + keystore.getType());
//        System.out.println("Size : " + keystore.size());
// 
//        Enumeration<?> en = keystore.aliases();
//        while (en.hasMoreElements()) {
//            System.out.println("Alias: " + en.nextElement());
//        }
//    }
    
	public void setTargetHostname(String value) {
		this.url = value;
		logger.info("Connection to: "+value);
	}
	
	public void setKeyStoreLocation(String property) {
		keyStoreFileName = property;
		trustStoreFileName = property;
	}
	
	public void setKeyStorePW(String property) {
		keyStorePassword = property;
		trustStorePassword = property;
	}

}
