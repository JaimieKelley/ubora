import java.io.*;
import java.net.*;
import redis.clients.jedis.*;


public class lightningClient {

    public static void main(String[] args) throws IOException {
	boolean DEBUG=false;
	String query = "";
	String manswer = "";
	String hostName = args[0];
	int port = Integer.parseInt(args[1]);
	String redisHost = args[2];
	int redisPort = Integer.parseInt(args[3]);
	InetAddress addr = InetAddress.getByName(hostName);
	int m = -1;
	int nco = 0;
	String s = args[4];

	PrintStream origOut = System.out;
	PrintStream interceptor = null;
	if (DEBUG) {
	    interceptor = new PrintStream("zout.lightningClient."+s);
	}
	else {
	    interceptor = new PrintStream("/dev/null");
	}
	System.setOut(interceptor);// just add the interceptor
	System.setErr(interceptor);// just add the interceptor

	nco++;
	if(s != null)
	    {
		query = s+ ":query";
		manswer = s+ ":manswer";
		Jedis jedis=null;
		    
		try{
		    jedis = new Jedis(redisHost,redisPort);
		    jedis.set(manswer,"");
		}
		catch (Exception jedisEx) {
		    System.out.println("Jedis Exception");
		    jedisEx.printStackTrace();
		    System.exit(-1);
		}
		try{
		    String value = null;
		    int retries = 0;
		    while ((value == null) && (retries < 20)) {
			value =jedis.get(query);
			retries++;
		    }

		    if (retries >= 20) {
			System.out.println("Unable to get query file in 20 tries");
			System.exit(-1);
		    }

			  
		    String lineD = value;
		    System.out.println(lineD);

		    String userInput, serverOutput;
		    long myTimer, secTime;
		    float secondTime;
		    long newTimer, newseconds;
		    float newTime;
		    float rate = (float) 0.5;
			  
		    newTimer = System.currentTimeMillis();
		    Socket oeSocket = new Socket();
		    oeSocket.setSoTimeout(8000);
		    oeSocket.setReceiveBufferSize(16384);
		    int connect_retries=0;
		    int max_retries = 10;
		    while (true) {
			try {
			    oeSocket.connect(new InetSocketAddress(addr, port), 1000);
			}
			catch (Exception e) {
			    if (connect_retries >= max_retries) {
				e.printStackTrace();
				System.exit(-1);
			    }
			    connect_retries++;
			}
			break;
		    }
		    PrintWriter out = new PrintWriter(oeSocket.getOutputStream(), true);
		    DataInputStream in = new DataInputStream(oeSocket.getInputStream());

		    out.println(lineD);
		    out.println("\n\n");
		    serverOutput="";
		    int iteration=0;
		    try {
			do {			      
			    byte bbuf[] = new byte[16384];
			    in.read(bbuf);
			    String serverOutput1 = new String(bbuf);
			    serverOutput = serverOutput + serverOutput1.trim();
			    System.out.println("Iteration: "+iteration);
			    iteration++;
			}while( iteration < 1000 );
		    }
		    catch (Exception timeout) {
			System.out.println("IO Exception " + timeout);
		timeout.printStackTrace();
		    }

		    jedis.set(manswer,serverOutput);
		    System.out.println("Server output: "+serverOutput);

		    m = -1;
		    myTimer = System.currentTimeMillis()-newTimer;
		    secondTime = myTimer/1000F;
		    System.out.println("It took " + secondTime + " seconds to answer this question.");
		    in.close();
		    out.close();
		    oeSocket.close();
			  
		} catch (UnknownHostException e) {
		    System.err.println("Don't know about host: " + addr.getHostName() + ".");
		    e.printStackTrace();
		} catch (IOException e) {
		    System.err.println("Couldn't get I/O for the connection to: " + addr.getHostName() + ".");
		    e.printStackTrace();
		}
	    }
    } 
}

