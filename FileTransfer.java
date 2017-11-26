import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.File;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.zip.CRC32;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.io.OutputStream;
import java.util.Scanner;

public class FileTransfer{

	public static void main(String[] args)throws Exception{
		Scanner sc = new Scanner(System.in);
		
		switch(args[0]){
			case "makekeys":
			//Generate a public/private RSA key pair and write their serialized forms to files public.bin and private.bin
				try{
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
					keyGen.initialize(4096);
					KeyPair keyPair = keyGen.genKeyPair();
					PrivateKey privateKey = keyPair.getPrivate();
					PublicKey publicKey = keyPair.getPublic();
					
					try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))){
						oos.writeObject(publicKey);
					}
					try(ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))){
						oos.writeObject(privateKey);
					}
				}
				catch(Exception e){
					e.printStackTrace(System.err);
				}
			
				break;

			case "server": 
				PrivateKey privateKey = (PrivateKey)new ObjectInputStream(new FileInputStream(new File(args[1]))).readObject();
				int serverPort = Integer.parseInt(args[2]);
				try(ServerSocket serverSocket = new ServerSocket(serverPort)){
					while(true){
						try{
							Socket socket = serverSocket.accept();
							Runnable server = () -> {
								try{
									String address = socket.getInetAddress().getHostAddress();
	                            	System.out.printf("Client connected: %s%n", address);
	                            	InputStream fromClient = socket.getInputStream();
	                            	ObjectInputStream objectFromClient = new ObjectInputStream(fromClient);
	                            	OutputStream toClient = socket.getOutputStream();
	                            	ObjectOutputStream objectToClient = new ObjectOutputStream(toClient);
	                            	int seq = 0;
	                            	Cipher c = null;
	                            	SecretKey decryptedSessionKey = null;
	                            	int totalChunks = 0;
	                            	int dataSize = 0;
	                            	byte[] datas = null;
	                            	ByteBuffer datasBuffer = null;
	                            	Message messageFromClient = null;
	                            	do{
	                            		messageFromClient = (Message) objectFromClient.readObject();
		                        		//if message is disconnect, close connection, and start a new thread that waits for connection
		                        		if(messageFromClient.getType().equals(MessageType.DISCONNECT)){
		                        			System.out.printf("Client disconnected: %s%n", address );
		                        			socket.close();
		                        			break;
		                        		}
		                        		//If the client sends a start message
		                        		else if(messageFromClient.getType().equals(MessageType.START)){
		                        			//prepare for a file transfer 
		                        			//decrypting the session key paaed by the client
		                        			StartMessage startMessage = (StartMessage)messageFromClient;
		                        			c = Cipher.getInstance("RSA");
		                        			c.init(Cipher.UNWRAP_MODE, privateKey);
		                        			decryptedSessionKey = (SecretKey) c.unwrap(startMessage.getEncryptedKey(), "AES",Cipher.SECRET_KEY);
		                        			//get total chunks
		                        			totalChunks = (int)startMessage.getSize()%startMessage.getChunkSize()>0 ? (int)startMessage.getSize()/startMessage.getChunkSize()+1 : dataSize/startMessage.getChunkSize();
		                        			//get data size
		                        			//System.out.println("total Chunks: "+totalChunks+" data sizedataSize);
		                        			dataSize = (int)startMessage.getChunkSize()*totalChunks;
		                        			//initalize data array
		                        			datas = new byte[dataSize];
		                        			//initialize byte buffer to buffers bytes to data array
		                        			datasBuffer = ByteBuffer.wrap(datas);
		                        			//after decrypting the session key, respond to the client with a ack message with sequence number 0
		                        			objectToClient.writeObject(new AckMessage(seq));
		                        		}
		                        		//if client sends a stop message, stop receiving and save the datas to the file name indicated in the stop message
		                        		else if(messageFromClient.getType().equals(MessageType.STOP)){
		                        			//discard associated file transfer
		                        			StopMessage stopMessage = (StopMessage)messageFromClient;
		                        			try{
		                        				//open a file with the file name in stop message
		                        				File file = new File(stopMessage.getFile());
		                        				//Write all reveived datas to file
		                        				FileOutputStream writeFile = new FileOutputStream(file);
		                        				writeFile.write(datasBuffer.array());
		                        				//close the file output stream
		                        				writeFile.close();
		                        				//indicate transfer is done
		                        				System.out.println("Transfer complete.");
		                        				System.out.println("Output path: "+stopMessage.getFile());
		                        			}
		                        			catch(Exception e){
		                        				e.printStackTrace();
		                        			}

		                        			//respond with an ack message with number -1
		                        			objectToClient.writeObject(new AckMessage(-1));
		                        		}
		                        		//if client sends in chunks
		                        		else if(messageFromClient.getType().equals(MessageType.CHUNK)){
		                        			Chunk chunk = (Chunk)messageFromClient;
		                        			//Check if the sequence number is equals to the expected sequence number
		                        			if(chunk.getSeq()==seq){		                        				
		                        				//decrypt data stored in the chunk using session from the transfer initialization step
		                        				c = Cipher.getInstance("AES");
		                        				c.init(Cipher.DECRYPT_MODE, decryptedSessionKey);
		                        				byte[] chunkData = c.doFinal(chunk.getData());
		                        				//buffers the decrypted data to the data array
		                        				datasBuffer.put(chunkData);
		                        				//calculate the CRC32 value for the decrypted data and compare it with the CRC32 value included in chunk
		                        				int dataCrc = getCRC(chunkData);
		                        				//if CRC32 match
		                        				if(dataCrc == chunk.getCrc()){
		                        					//increament seq by 1
		                        					seq++;
		                        					//respond ack to client by sending the expected sequence as the ack message
		                        					objectToClient.writeObject(new AckMessage(seq));
		                        					System.out.printf("Chunk received [%d/%d]\n", seq, totalChunks);
		                        				}
		                        					
		                        			}
		                        			else{
		                        				//respond the current sequence to client
		                        				objectToClient.writeObject(new AckMessage(seq));
		                        			}
		                        		}
	                            	}while(true);//run until the disconnect message break this loop
	                        		objectToClient.close();
									objectFromClient.close();
									
								}
								catch(Exception e){
									e.printStackTrace();
								}
							};
							Thread serverThread = new Thread(server);
							serverThread.start();

						}
						catch(Exception e){
							e.printStackTrace();
						}
						
					}
					
				}
				catch(Exception e){
					e.printStackTrace();
				}
				

				break;
			case "client": 
				PublicKey publicKey = (PublicKey)new ObjectInputStream(new FileInputStream(new File(args[1]))).readObject();
				String host = args[2];
				int port = Integer.parseInt(args[3]);
				//connect to sever
				try(Socket socket = new Socket(host, port)){
					
					OutputStream toServer = socket.getOutputStream();
					ObjectOutputStream sendObjectToServer = new ObjectOutputStream(toServer);
					InputStream fromServer = socket.getInputStream();
					ObjectInputStream objectFromServer = new ObjectInputStream(fromServer);
					//display connection message
					System.out.println("Connect to server: "+socket.getInetAddress().toString());
					//Generate AES session key
		            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		            keyGen.init(128);
		           	SecretKey sessionKey = keyGen.generateKey();
		           	//Encrypt the session key using the server's public key
		           	Cipher c = Cipher.getInstance("RSA");
		           	c.init(Cipher.WRAP_MODE, publicKey);
		           	byte[] wrapKey = c.wrap(sessionKey);
		           	//Get file path
		           	System.out.print("Enter path:");
		           	String filePath = sc.nextLine();
		           	filePath = filePath+".txt";
		           	File file = new File(filePath);

		           	//if file exist
		           	if(file.exists()){
		           		//get chunk size
		           		System.out.print("Enter chunk size [1024]: ");
		           		int chunkSize = sc.nextInt();
		           		//send start message
		           		StartMessage startMessage = new StartMessage(filePath,wrapKey, chunkSize);
			           	sendObjectToServer.writeObject(startMessage);
			           	AckMessage ackMessage = (AckMessage)objectFromServer.readObject();
			           	
			           	int totalChunks = (int)file.length()/chunkSize;
			           	if((int)file.length()%chunkSize!=0){
			           		totalChunks++;
			           	}
			           	FileInputStream readFile = new FileInputStream(file);
			           	System.out.println("Sending: "+filePath+" File Size: "+file.length());
			           	System.out.printf("Sending %d chunks.\n", totalChunks);
			           	do{
			           		
							//objectFromServer = new ObjectInputStream(fromServer);
			           		if(ackMessage.getSeq() != -1){
			           			
				           		byte[] datas = new byte[chunkSize];
				           		readFile.read(datas);
				           		//encrytp data
				           		c = Cipher.getInstance("AES");
				           		c.init(Cipher.ENCRYPT_MODE, sessionKey);
				           		byte[] dataEncrypted = c.doFinal(datas);
				           		int dataCrc = getCRC(datas);
				           		Chunk chunk = new Chunk(ackMessage.getSeq(), dataEncrypted, dataCrc);
				           		sendObjectToServer.writeObject(chunk);
				           		int counter = ackMessage.getSeq()+1;
				           		System.out.printf("Chunks completed [%d/%d]\n",counter, totalChunks );
				           		ackMessage = (AckMessage) objectFromServer.readObject();
			           		}
			           		
			           	}while(ackMessage.getSeq()<totalChunks);
			           	sendObjectToServer.writeObject(new StopMessage("test2.txt"));
			           	sendObjectToServer.writeObject(new DisconnectMessage());
			           	objectFromServer.close();
						sendObjectToServer.close();
						readFile.close();
		           	}
		           	
				}

				break;
			default: break;
		}
	}
	public static int getCRC(byte[] datas){
		CRC32 crc = new CRC32();
		crc.update(datas);
		return(int)crc.getValue();
	}
}