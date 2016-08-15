/**
 * KMIPClientHandler.java
 * ------------------------------------------------------------------
 *     __ __ __  ___________ 
 *    / //_//  |/  /  _/ __ \	  .--.
 *   / ,<  / /|_/ // // /_/ /	 /.-. '----------.
 *  / /| |/ /  / // // ____/ 	 \'-' .--"--""-"-'
 * /_/ |_/_/  /_/___/_/      	  '--'
 * 
 * ------------------------------------------------------------------
 * Description:
 * The KMIPClientHandler provides a Thread, which handles the client-
 * requests to the server, as well the read and write service to the 
 * server via TCP-Sockets. 
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

package ch.ntb.inf.kmip.stub.transport;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;

class KMIPClientHandler implements Callable<ArrayList<Byte>> {

	private static final Logger logger = LoggerFactory.getLogger(KMIPClientHandler.class);
	
	private int port;
	private String targetHostname;
	private ArrayList<Byte> encodedMessage;
	private Socket clientSocket;

	private String keyStorePassword;
	private String keyStoreFileName;
	private String certificateAlias;
	
	public KMIPClientHandler(String targetHostname, int port,
							 ArrayList<Byte> encodedMessage,
							 String keyStoreFileName, String keyStorePassword,
							 String certificateAlias){
		this.port = port;
		this.targetHostname = targetHostname;
		this.encodedMessage = encodedMessage;
		this.keyStoreFileName = keyStoreFileName;
		this.keyStorePassword = keyStorePassword;
		this.certificateAlias = certificateAlias;
	}

	private static KeyManager[] createKeyManagers(String keyStoreFileName, String keyStorePassword, String certificateAlias)
            throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {

		java.io.InputStream inputStream = new java.io.FileInputStream(keyStoreFileName);

		// Create KeyStore object, load it with keyStoreFileName data
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(inputStream, keyStorePassword == null ? null : keyStorePassword.toCharArray());

		KeyManager[] managers;
		if (certificateAlias != null) {
			managers = new KeyManager[] {new AliasKeyManager(keyStore, certificateAlias, keyStorePassword)};
		} else {
			// Create KeyManagerFactory load the KeyStore object in it
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(keyStore, keyStorePassword == null ? null : keyStorePassword.toCharArray());
			managers = keyManagerFactory.getKeyManagers();
		}
		return managers;
	}
	private static TrustManager[] createSystemTrustManagers()
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        // We also need to look into loading up the local keystore as the trust manager.
		// Get Java's default trust managers
		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

		// Initialize with null to get the system default trust managers.
		tmf.init((KeyStore)null);

		return tmf.getTrustManagers();

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

    // Call method for the FutureTask (similar to run() of a Thread)
	public ArrayList<Byte> call() throws KeyManagementException {
		logger.info("ClientHandler:" + Thread.currentThread());
		// Start a server-request
		// Create a Socket for the TCP Client and build up the communication to the corresponding server.

        SSLContext context;
        KeyManager[] keyManagers;
        TrustManager[] trustManagers;

        // Initialize the SSL context.
        try{
            context = SSLContext.getInstance("TLSv1.2");
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
        try {
            keyManagers = createKeyManagers(this.keyStoreFileName, this.keyStorePassword, this.certificateAlias);
        } catch (CertificateException e) {
            throw new AssertionError(e);
        } catch (IOException e) {
            throw new AssertionError(e);
        } catch (KeyStoreException e) {
            throw new AssertionError(e);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        } catch (UnrecoverableKeyException e) {
            throw new AssertionError(e);
        }
        try {
            trustManagers = createTrustManagers(this.keyStoreFileName, this.keyStorePassword);
        } catch (KeyStoreException e) {
            throw new AssertionError(e);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        } catch (CertificateException e) {
            throw new AssertionError(e);
        } catch (IOException e) {
            throw new AssertionError(e);
        }

        context.init(keyManagers, trustManagers, new SecureRandom());

        removeUnsafeProtocols(context);



        try {

			clientSocket = context.getSocketFactory().createSocket(targetHostname, port);
			// Send to server
			logger.info("Write Data to Server...");  
			writeData(clientSocket);
			logger.info("Data transmitted!");
			
			// Close output signalize EOF
			clientSocket.shutdownOutput();
			
			// Read from server
			ArrayList<Byte> responseFromServer = readData();
			
			// Close connection
			clientSocket.close();
			
			return responseFromServer;
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;	
		} 
	}

    private void removeUnsafeProtocols(SSLContext context) {
        // Setting up SSL Parameters for TLS
        SSLParameters sslParameters = context.getDefaultSSLParameters();
        // Do not send an SSL-2.0-compatible Client Hello.
        ArrayList<String> protocols = new ArrayList<String>(
                Arrays.asList(sslParameters.getProtocols()));
        protocols.remove("SSLv2Hello");
        sslParameters.setProtocols(protocols.toArray(new String[protocols.size()]));

        // Adjust the supported ciphers.
        ArrayList<String> ciphers = new ArrayList<String>(
                Arrays.asList(sslParameters.getCipherSuites()));
        // TODO: Determine which ciphers are FIPS 140-2 validated.
        ciphers.retainAll(Arrays.asList(
                "TLS_RSA_WITH_AES_128_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
                "SSL_RSA_WITH_RC4_128_SHA1",
                "SSL_RSA_WITH_RC4_128_MD5",
                "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"));
        sslParameters.setCipherSuites(ciphers.toArray(new String[ciphers.size()]));
    }


    private void writeData(Socket clientSocket){
		try {
			// Get OutputStream from Socket
			DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
			// Prepare data to send
			byte[] b = new byte[encodedMessage.size()];
			for(int i=0; i<encodedMessage.size();i++){
				b[i]=encodedMessage.get(i);
			}
			// Send data
			outToServer.write(b);
			outToServer.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	} 

	private ArrayList<Byte> readData(){
    	byte[] resultBuff = new byte[0];
        byte[] buff = new byte[1024];
        int k;
        
        try {
    		InputStream is = clientSocket.getInputStream();
			while((k = is.read(buff, 0, buff.length)) > -1) {
			    byte[] tbuff = new byte[resultBuff.length + k]; // temp buffer size = bytes already read + bytes last read
			    System.arraycopy(resultBuff, 0, tbuff, 0, resultBuff.length); // copy previous bytes
			    System.arraycopy(buff, 0, tbuff, resultBuff.length, k);  // copy current lot
			    resultBuff = tbuff; // call the temp buffer as your result buff
			}
		} catch (IOException e) {
			e.printStackTrace();
		} // try
       
        logger.debug(resultBuff.length + " bytes read.");
        ArrayList<Byte> response = new ArrayList<>();
        
        for(byte b:resultBuff){
        	response.add(b);
        }
        
        logger.info("");  
        return response;
	} 
} 
