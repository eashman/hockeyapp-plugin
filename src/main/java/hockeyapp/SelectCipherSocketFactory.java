package hockeyapp;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.apache.http.conn.ssl.SSLSocketFactory;

/**
 * Custom SSLSocketFactory to exclude some ciphers that cause problems 
 * with OpenJDK 7. 
 * 
 * @author Thomas Dohmke
 */
public class SelectCipherSocketFactory extends SSLSocketFactory {
	private javax.net.ssl.SSLSocketFactory socketFactory;

	public SelectCipherSocketFactory(SSLContext context) {
		super(context);
		this.socketFactory = context.getSocketFactory();
	}

	public Socket createSocket() throws IOException {
		SSLSocket socket = (SSLSocket)super.createSocket();
		filterCipherSuites(socket);
		return socket;
	}
	
	public Socket createSocket(final Socket socket, final String host, final int port, final boolean autoClose) throws IOException, UnknownHostException {
        SSLSocket sslSocket = (SSLSocket) this.socketFactory.createSocket(socket, host, port, autoClose);
		filterCipherSuites(sslSocket);
		return sslSocket;
    }	
	
	private void filterCipherSuites(SSLSocket socket) {
		String suites[] = socket.getEnabledCipherSuites();
		final List<String> list =  new ArrayList<String>();
	    Collections.addAll(list, suites);
	    list.remove("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
		socket.setEnabledCipherSuites(list.toArray(new String[list.size()]));
	}
}
