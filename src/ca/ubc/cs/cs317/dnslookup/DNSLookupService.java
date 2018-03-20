package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.io.IOException;
import java.util.*;


public class DNSLookupService {

  private static final int DEFAULT_DNS_PORT = 53;
  private static final int MAX_INDIRECTION_LEVEL = 10;

  private static InetAddress rootServer;
  private static boolean verboseTracing = false;
  private static DatagramSocket socket;

  private static DNSCache cache = DNSCache.getInstance();

  private static Random random = new Random();
  private static int[] generatedQueryIDs = new int[65536];
  private static int totalQueryCount = 0;
  private static int pointer = 0; // global pointer for decoding query

  /**
   * Main function, called when program is first invoked.
   *
   * @param args list of arguments specified in the command line.
   */
  public static void main(String[] args) {

    if (args.length != 1) {
      System.err.println("Invalid call. Usage:");
      System.err.println("\tjava -jar DNSLookupService.jar rootServer");
      System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
      System.exit(1);
    }

    try {
      rootServer = InetAddress.getByName(args[0]);
      System.out.println("Root DNS server is: " + rootServer.getHostAddress());
    } catch (UnknownHostException e) {
      System.err.println("Invalid root server (" + e.getMessage() + ").");
      System.exit(1);
    }

    try {
      socket = new DatagramSocket();
      socket.setSoTimeout(5000);
    } catch (SocketException ex) {
      ex.printStackTrace();
      System.exit(1);
    }

    Scanner in = new Scanner(System.in);
    Console console = System.console();
    do {
      // Use console if one is available, or standard input if not.
      String commandLine;
      if (console != null) {
        System.out.print("DNSLOOKUP> ");
        commandLine = console.readLine();
      } else
        try {
          commandLine = in.nextLine();
        } catch (NoSuchElementException ex) {
          break;
        }
      // If reached end-of-file, leave
      if (commandLine == null) break;

      // Ignore leading/trailing spaces and anything beyond a comment character
      commandLine = commandLine.trim().split("#", 2)[0];

      // If no command shown, skip to next command
      if (commandLine.trim().isEmpty()) continue;

      String[] commandArgs = commandLine.split(" ");

      if (commandArgs[0].equalsIgnoreCase("quit") ||
          commandArgs[0].equalsIgnoreCase("exit"))
        break;
      else if (commandArgs[0].equalsIgnoreCase("server")) {
        // SERVER: Change root nameserver
        if (commandArgs.length == 2) {
          try {
            rootServer = InetAddress.getByName(commandArgs[1]);
            System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
          } catch (UnknownHostException e) {
            System.out.println("Invalid root server (" + e.getMessage() + ").");
            continue;
          }
        } else {
          System.out.println("Invalid call. Format:\n\tserver IP");
          continue;
        }
      } else if (commandArgs[0].equalsIgnoreCase("trace")) {
        // TRACE: Turn trace setting on or off
        if (commandArgs.length == 2) {
          if (commandArgs[1].equalsIgnoreCase("on"))
            verboseTracing = true;
          else if (commandArgs[1].equalsIgnoreCase("off"))
            verboseTracing = false;
          else {
            System.err.println("Invalid call. Format:\n\ttrace on|off");
            continue;
          }
          System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
        } else {
          System.err.println("Invalid call. Format:\n\ttrace on|off");
          continue;
        }
      } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
          commandArgs[0].equalsIgnoreCase("l")) {
        // LOOKUP: Find and print all results associated to a name.
        RecordType type;
        if (commandArgs.length == 2)
          type = RecordType.A;
        else if (commandArgs.length == 3)
          try {
            type = RecordType.valueOf(commandArgs[2].toUpperCase());
          } catch (IllegalArgumentException ex) {
            System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
            continue;
          }
        else {
          System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
          continue;
        }
        findAndPrintResults(commandArgs[1], type);
      } else if (commandArgs[0].equalsIgnoreCase("dump")) {
        // DUMP: Print all results still cached
        cache.forEachNode(DNSLookupService::printResults);
      } else {
        System.err.println("Invalid command. Valid commands are:");
        System.err.println("\tlookup fqdn [type]");
        System.err.println("\ttrace on|off");
        System.err.println("\tserver IP");
        System.err.println("\tdump");
        System.err.println("\tquit");
        continue;
      }

    } while (true);

    socket.close();
    System.out.println("Goodbye!");
  }

  /**
   * Finds all results for a host name and type and prints them on the standard output.
   *
   * @param hostName Fully qualified domain name of the host being searched.
   * @param type   Record type for search.
   */
  private static void findAndPrintResults(String hostName, RecordType type) {

    DNSNode node = new DNSNode(hostName, type);
    printResults(node, getResults(node, 0));
  }

  /**
   * Finds all the result for a specific node.
   *
   * @param node       Host and record type to be used for search.
   * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
   *             The initial call should be made with 0 (zero), while recursive calls for
   *             regarding CNAME results should increment this value by 1. Once this value
   *             reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
   *             returns an empty set.
   * @return A set of resource records corresponding to the specific query requested.
   */
  private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
    InetAddress nameServer = rootServer;

    if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
      System.err.println("Maximum number of indirection levels reached.");
      return Collections.emptySet();
    }

    // If the information is in the cache, return it directly
    Set<ResourceRecord> cachedResults = cache.getCachedResults(node);
    if (!cachedResults.isEmpty()){
      return cachedResults;
    }

    DNSNode cnameNode = new DNSNode(node.getHostName(), RecordType.getByCode(5));

    // Max 20 iterations
    for(int i = 0; i < 20; i++){
      // Check if we have CNAME in the cache
      cachedResults = cache.getCachedResults(cnameNode);
      if (cachedResults.isEmpty()){
        // We don't have CNAME in cache
        if (nameServer != null) {
          nameServer = retrieveResultsFromServer(node, nameServer);
          // update cache results
          cachedResults = cache.getCachedResults(node);
          if (!cachedResults.isEmpty()){
            return cachedResults;
          }
        }
      } else {
        // start new query with CNAME and node's type
        Set<ResourceRecord> allResults = new HashSet<ResourceRecord>();
        for (ResourceRecord cnameRecord : cachedResults){
          DNSNode newNode = new DNSNode(cnameRecord.getTextResult(), node.getType());
          allResults.addAll(getResults(newNode, indirectionLevel + 1));
        }
        return allResults;
      }
    }

    return Collections.emptySet();
  }

  /**
  * Method to encode query as a message in the domain protocol
  *
  * @param queryID uniquely generated ID
  * @param node Host name and record type to be used for the query.
  * @return encoded query in a byte array
  **/
  private static byte[] encodeQuery(int queryID, DNSNode node) {
    byte[] queryBuffer = new byte[512];
    int thirdByte = queryID >>> 8;
    int forthByte = queryID & 0xff;
    queryBuffer[0] = (byte) thirdByte;
    queryBuffer[1] = (byte) forthByte;
    int QROpcodeAATCRD = 0; // 0 iterative, 1 recursive
    queryBuffer[2] = (byte) QROpcodeAATCRD;
    int RAZRCODE = 0;
    queryBuffer[3] = (byte) RAZRCODE;
    int QDCOUNT = 1;
    queryBuffer[4] = (byte) 0;
    queryBuffer[5] = (byte) QDCOUNT;
    int ANCOUNT = 0;
    queryBuffer[6] = (byte) 0;
    queryBuffer[7] = (byte) ANCOUNT;
    int NSCOUNT = 0;
    queryBuffer[8] = (byte) 0;
    queryBuffer[9] = (byte) NSCOUNT;
    int ARCOUNT = 0;
    queryBuffer[10] = (byte) 0;
    queryBuffer[11] = (byte) ARCOUNT;
    int ptr = 12;
    String[] labels = node.getHostName().split("\\.");
    for (int i = 0 ; i < labels.length; i++) {
      String label = labels[i];
      queryBuffer[ptr++] = (byte) label.length();
      for (char c : label.toCharArray()) {
        queryBuffer[ptr++] = (byte) ((int) c);
      }
    }
    queryBuffer[ptr++] = (byte) 0; //end of QNAME
    int QTYPE = node.getType().getCode();
    queryBuffer[ptr++] = (byte) ((QTYPE >>> 8) & 0xff);
    queryBuffer[ptr++] = (byte) (QTYPE & 0xff);
    int QCLASS = 1; // always Internet(IN)
    queryBuffer[ptr++] = (byte) 0;
    queryBuffer[ptr++] = (byte) QCLASS;
    return Arrays.copyOfRange(queryBuffer, 0, ptr);
  }

  /**
  * Helper function that finds int value of 2 bytes (short to int)
  *
  * @param b1 left byte
  * @param b2 right byte
  * @return 256 * b1 + b2 as integer
  **/
  private static int getIntFromTwoBytes(byte b1, byte b2) {
    return ((b1 & 0xFF) << 8) + (b2 & 0xFF);
  }

  /**
  * Helper function that finds int value of 4 bytes (4 bytes to int)
  *
  * @param b1 first byte
  * @param b2 second byte
  * @param b3 third byte
  * @param b4 fourth byte
  * @return 16777216 * b1 + 65536 * b2 + 256 * b3 + b4 as integer
  **/
  private static int getIntFromFourBytes(byte b1, byte b2, byte b3, byte b4) {
    return ((b1 & 0xFF) << 24) + ((b2 & 0xFF) << 16) + ((b3 & 0xFF) << 8) + (b4 & 0xFF);
  }

  /**
  * Recursively resolve the compressed name starting from ptr
  *
  * @param buffer byte array to be resolved
  * @param ptr initial location to start resolving
  * @return resolved compressed name
  **/
  private static String getNameFromPointer(byte[] buffer, int ptr){
    String name = "";
    while(true) {
      int labelLength = buffer[ptr++] & 0xFF;
      if (labelLength == 0)
        break;
      // Identify message compression used, recursive call to retrieve name
      else if (labelLength >= 192) {
        int newPtr = (buffer[ptr++] & 0xFF) + 256 * (labelLength - 192);
        name += getNameFromPointer(buffer, newPtr);
        break;
      }
      // standard function to decode encoded name
      else {
        for (int i = 0; i < labelLength; i++) {
          char ch = (char) (buffer[ptr++] & 0xFF);
          name += ch;
        }
        name += '.';
      }
    }

    pointer = ptr;
    if (name.length() > 0 && name.charAt(name.length() - 1) == '.') {
      name = name.substring(0, name.length() - 1);
    }
    return name;
  }


  /**
  * Decode single RR in one of the following fields: answers, nameservers or
  * additional information, put it to cache if it's answer or additional info
  *
  * @param responseBuffer received response from DNS server
  * @param cacheRecord boolean value that indicates if the result should be
  *                     cached or not
  * @return decoded resource record
  **/
  private static ResourceRecord decodeSingleRecord(byte[] responseBuffer, boolean cacheRecord){
    ResourceRecord record = null;
    String hostName = getNameFromPointer(responseBuffer, pointer);
    int typeCode = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
    int classCode = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
    long TTL = getIntFromFourBytes(responseBuffer[pointer++], responseBuffer[pointer++], responseBuffer[pointer++], responseBuffer[pointer++]);
    int RDATALength = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
    boolean errorOccured = false;
    if (typeCode == 1) { // A IPv4
      String address = "";
      for (int j = 0; j < RDATALength; j++) {
        int octet = responseBuffer[pointer++] & 0xFF;
        address += octet + ".";
      }
      address = address.substring(0, address.length() - 1);
      InetAddress addr = null;
      try {
        addr = InetAddress.getByName(address);
        record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, addr);
        verbosePrintResourceRecord(record, 0);
      } catch (UnknownHostException e){
        errorOccured = true;
      }
    }
    else if (typeCode == 28) { // AAAA IPv6
      String address = "";
      for (int j = 0; j < RDATALength / 2; j++) {
        int octet = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
        String hex = Integer.toHexString(octet);
        address += hex + ":";
      }
      address = address.substring(0, address.length() - 1);
      InetAddress addr = null;
      try {
        addr = InetAddress.getByName(address);
        record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, addr);
        verbosePrintResourceRecord(record, 0);
      } catch (UnknownHostException e){
        errorOccured = true;
      }
    } else if (typeCode == 2 || typeCode == 5 || typeCode == 6) { // NS or CNAME or SOA
      String data = getNameFromPointer(responseBuffer, pointer);
      record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, data);
      verbosePrintResourceRecord(record, 0);
    }
    else { // all other types are assumed to have value like NS or CNAME
      String data = getNameFromPointer(responseBuffer, pointer);
      record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, data);
      verbosePrintResourceRecord(record, 0);
    }

    if (!errorOccured && cacheRecord) {
      cache.addResult(record);
    }
    return record;
  }

  /**
  * Method to decode response header
  * This method calls decodeSingleRecord for fields next to header
  * @param queryID generated unique query ID
  * @param node Host name and record type to be used for the query.
  * @param responseBuffer received response from the DNS server
  * @return possible nameservers that can be used in the next iteration
  **/
  private static ArrayList<ResourceRecord> decodeResponse(int queryID, DNSNode node, byte[] responseBuffer) {
    int responseID = getIntFromTwoBytes(responseBuffer[0],responseBuffer[1]);
    int QR = (responseBuffer[2] & 0x80) >>> 7; // get 1st bit
    int opCode = (responseBuffer[2] & 0x78) >>> 3; // get 2nd, 3rd, 4th and 5th bit
    int AA = (responseBuffer[2] & 0x04) >>> 2; // geth 6th
    int TC = (responseBuffer[2] & 0x02) >>> 1; // get 7th bit
    int RD = responseBuffer[2] & 0x01; // get 8th bit

    if (verboseTracing)
      System.out.println("Response ID: " + responseID + " Authoritative = " + (AA == 1));

    int RA = responseBuffer[3] & 0x80;
    int RCODE = responseBuffer[3] & 0x0F;
    String message = "";
    switch (RCODE) {
      case 0: message = "OK. No error on RCODE";
          break;
      case 1: message = "FAILED. Format error, name server didn't understand query";
          break;
      case 2: message = "FAILED. Server error";
          break;
      case 3: message = "FAILED. Name error – the name doesn't exist";
          break;
      case 4: message = "FAILED. Support for query not implemented";
          break;
      case 5: message = "FAILED. Request refused";
          break;
      default: message = "FAILED. Unknown RCODE";
          break;
    }

    int QDCOUNT = getIntFromTwoBytes(responseBuffer[4], responseBuffer[5]);
    int ANCOUNT = getIntFromTwoBytes(responseBuffer[6], responseBuffer[7]);
    int NSCOUNT = getIntFromTwoBytes(responseBuffer[8], responseBuffer[9]);
    int ARCOUNT = getIntFromTwoBytes(responseBuffer[10], responseBuffer[11]);
    pointer = 12;
    String receivedQNAME = "";
    while(true) {
      int labelLength = responseBuffer[pointer++] & 0xFF;
      if (labelLength == 0)
        break;
      for (int i = 0; i < labelLength; i++) {
        char ch = (char) (responseBuffer[pointer++] & 0xFF);
        receivedQNAME += ch;
      }
      receivedQNAME += '.';
    }
    //receivedQNAME = receivedQNAME.substring(0, receivedQNAME.length() - 1);
    int QTYPE = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
    int QCLASS = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);

    ResourceRecord record = null;

    if (verboseTracing)
      System.out.println("  Answers (" + ANCOUNT + ")");
    for (int i=0; i < ANCOUNT; i++) {
      decodeSingleRecord(responseBuffer, true);
    }

    ArrayList<ResourceRecord> nameServers = new ArrayList<ResourceRecord>();
    if (verboseTracing)
      System.out.println("  Nameservers (" + NSCOUNT + ")");
    for (int i=0; i < NSCOUNT; i++) {
      record = decodeSingleRecord(responseBuffer, true);
      if (record != null) {
        nameServers.add(record);
      }
    }

    ArrayList<ResourceRecord> additionals = new ArrayList<ResourceRecord>();
    if (verboseTracing)
      System.out.println("  Additional Information (" + ARCOUNT + ")");
    for (int i=0; i < ARCOUNT; i++) {
      record = decodeSingleRecord(responseBuffer, true);
      if (record != null) {
        additionals.add(record);
      }
    }

    if (AA == 1 || RCODE != 0){
      return null;
    } else { // AA = 0 case
      ArrayList<ResourceRecord> authNameServers = new ArrayList<ResourceRecord>();
      for (ResourceRecord nameserver: nameServers) {
        String name = nameserver.getTextResult();
        for (ResourceRecord additional: additionals) {
          if (additional.getHostName().equals(name) && additional.getType().getCode() == 1){
            // A records for name servers
            authNameServers.add(additional);
          }
        }
      }
      if (authNameServers.isEmpty()){
        for (ResourceRecord nameserver: nameServers) {
          String name = nameserver.getTextResult();
          // search for nameserver A record
          DNSNode nsServerNode = new DNSNode(name, RecordType.getByCode(1));
          Set<ResourceRecord> newResults = getResults(nsServerNode, 0);
          if (!newResults.isEmpty()){
            authNameServers.addAll(newResults);
            break;
          }
        }
      }
      return authNameServers; // If none of `getResults` returns a non-empty list, HARDCORE FAIL
    }
  }

  /**
   * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
   * and the query is repeated with a new server if the provided one is non-authoritative.
   * Results are stored in the cache.
   *
   * @param node   Host name and record type to be used for the query.
   * @param server Address of the server to be used for the query.
   **/
  private static InetAddress retrieveResultsFromServer(DNSNode node, InetAddress server) {
    int queryID = getNewUniqueQueryID();
    byte[] queryBuffer = encodeQuery(queryID, node);
    int timeOutCount = 0;
    int maxTimeOutCount = 2;
    while(timeOutCount < maxTimeOutCount) {
      if (verboseTracing) {
        System.out.print("\n\n");
        System.out.println("Query ID   " + queryID + " " + node.getHostName() + "  " + node.getType() + " --> " + server.getHostAddress());
      }

      DatagramPacket queryPacket = new DatagramPacket(queryBuffer, queryBuffer.length, server, DEFAULT_DNS_PORT);
      try {
        socket.send(queryPacket);
      } catch (IOException e) {
        break;
      }

      byte[] responseBuffer = new byte[1024];
      DatagramPacket responsePacket = new DatagramPacket(responseBuffer, responseBuffer.length);
      try {
        socket.receive(responsePacket);
        int responseID = getIntFromTwoBytes(responseBuffer[0],responseBuffer[1]);
        int QR = (responseBuffer[2] & 0x80) >>> 7; // get 1st bit

        while (queryID != responseID || QR != 1) {
          socket.receive(responsePacket);
          responseID = getIntFromTwoBytes(responseBuffer[0],responseBuffer[1]);
          QR = (responseBuffer[2] & 0x80) >>> 7; // get 1st bit
        }

        ArrayList<ResourceRecord> authNameServers = decodeResponse(queryID, node, responseBuffer);
        if (authNameServers == null || authNameServers.isEmpty()) {
          return null;
        } else {
          ResourceRecord firstNameServer = authNameServers.get(0);
          return firstNameServer.getInetResult();
        }
      } catch (SocketTimeoutException e) {
        timeOutCount++;
      } catch (IOException e) {
        break;
      }
    }
    return null;
  }

  /**
  * Prints given buffer array in hexadecimal base
  *
  * @param buffer byte array to be printed in hexadecimal base
  **/
  private static void printBufferHexDump(byte[] buffer) {
    for (int x = 0 ; x < buffer.length; x++) {
      System.out.print(String.format("%02x ", buffer[x]));
    }
    System.out.println();
  }

  private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
    if (verboseTracing)
      System.out.format("     %-30s %-10d %-4s %s\n", record.getHostName(),
          record.getTTL(),
          record.getType() == RecordType.OTHER ? rtype : record.getType(),
          record.getTextResult());
  }

  /**
   * Prints the result of a DNS query.
   *
   * @param node  Host name and record type used for the query.
   * @param results Set of results to be printed for the node.
   */
  private static void printResults(DNSNode node, Set<ResourceRecord> results) {
    if (results.isEmpty())
      System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
          node.getType(), -1, "0.0.0.0");
    for (ResourceRecord record : results) {
      System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
          node.getType(), record.getTTL(), record.getTextResult());
    }
  }

  /**
  * Generates a random ID between 0 and 655536, if it's generated before,
  * tries until generating a unique one
  *
  * @return a new and unique query ID
  **/
  private static int getNewUniqueQueryID() {
    int next = random.nextInt(65536);
    for (int i = 0; i < totalQueryCount; i++){
      if (generatedQueryIDs[i] == next) {
        return getNewUniqueQueryID();
      }
    }
    generatedQueryIDs[totalQueryCount++] = next;
    return next;
  }
}
