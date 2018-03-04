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
    private static int pointer = 0; // pointer for decoding query

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
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
        InetAddress nameServer = rootServer;

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        Set<ResourceRecord> cachedResults = cache.getCachedResults(node);
        if (!cachedResults.isEmpty()){
            return cachedResults;
        }

        while(true){
            nameServer = retrieveResultsFromServer(node, nameServer);
            cachedResults = cache.getCachedResults(node); // update cache results
            if (cachedResults.isEmpty() && nameServer == null) {
                return Collections.emptySet();
            } else if (!cachedResults.isEmpty()){
                return cachedResults;
            }
        }
    }

    private static byte[] encodeQuery(int queryID, DNSNode node) {
        byte[] queryBuffer = new byte[512];
        int thirdBit = queryID >>> 8;
        int forthBit = queryID & 0xffffff;
        queryBuffer[0] = (byte) thirdBit;
        queryBuffer[1] = (byte) forthBit;
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
        queryBuffer[ptr++] = (byte) 0;
        queryBuffer[ptr++] = (byte) QTYPE;
        int QCLASS = 1; // always Internet(IN)
        queryBuffer[ptr++] = (byte) 0;
        queryBuffer[ptr++] = (byte) QCLASS;
        return Arrays.copyOfRange(queryBuffer, 0, ptr);
    }

    private static int getIntFromTwoBytes(byte b1, byte b2) {
        return ((b1 & 0xFF) << 8) + (b2 & 0xFF);
    }

    private static int getIntFromFourBytes(byte b1, byte b2, byte b3, byte b4) {
        return ((b1 & 0xFF) << 24) + ((b2 & 0xFF) << 16) + ((b3 & 0xFF) << 8) + (b4 & 0xFF);
    }

    private static String getNameFromPointer(byte[] buffer, int ptr){
        String name = "";
        while(true) {
            int labelLength = buffer[ptr++] & 0xFF;
            if (labelLength == 0)
                break;
            else if (labelLength == 192) { // compressed data, recursive call
                int newPtr = (buffer[ptr++] & 0xFF);
                name += getNameFromPointer(buffer, newPtr);
                break;
            }
            else {
                for (int i = 0; i < labelLength; i++) {
                    char ch = (char) (buffer[ptr++] & 0xFF);
                    name += ch;
                }
                name += '.';
            }
        }
        return name.substring(0, name.length() - 1);
    }

    private static ResourceRecord decodeSingleRecord(byte[] responseBuffer, boolean cacheRecord){
        int c0 = (responseBuffer[pointer++] & 0xFF);
        ResourceRecord record = null;
        if (c0 == 192) { // Compressed data
            int hostNamePointer = (responseBuffer[pointer++] & 0xFF);
            String hostName = getNameFromPointer(responseBuffer, hostNamePointer);
            int typeCode = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
            int classCode = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
            long TTL = getIntFromFourBytes(responseBuffer[pointer++], responseBuffer[pointer++], responseBuffer[pointer++], responseBuffer[pointer++]);
            int RDATALength = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
            boolean cacheable = true;
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
                    System.out.println("FAILED, cannot getByName address");
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
                    System.out.println("FAILED, cannot getByName address");
                }
            } else if (typeCode == 2) { // NS
                String data = getNameFromPointer(responseBuffer, pointer);
                pointer += RDATALength;  // move pointer length of r-data times
                record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, data);
                verbosePrintResourceRecord(record, 0);
            } else if (typeCode == 5) { // CNAME
                String data = getNameFromPointer(responseBuffer, pointer);
                pointer += RDATALength;  // move pointer length of r-data times
                record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, data);
                verbosePrintResourceRecord(record, 0);
            }
            else {
                cacheable = false;
                // we need to skip here
                // assume that next record starts with c0 = 192
                // what if there is no next record??? - limit searching with 100
                System.out.println("FAILED. Need to handle type: " + typeCode);
                String data = getNameFromPointer(responseBuffer, pointer);
                pointer += RDATALength;  // move pointer length of r-data times
                record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, data);
                verbosePrintResourceRecord(record, 0);
            }

            if (cacheable && cacheRecord) {
                cache.addResult(record);
            }
        } else {
            System.out.println(Integer.toHexString(responseBuffer[pointer] & 0xFF));
            System.out.println("FAILED. c0 is expected. Check your pointers!");
        }

        return record;
    }

    private static ArrayList<ResourceRecord> decodeResponse(int queryID, DNSNode node, byte[] responseBuffer) {
        int receivedQueryID = getIntFromTwoBytes(responseBuffer[0],responseBuffer[1]);

        if (queryID != receivedQueryID) {
            System.out.println("FAILED. Response does not have same query ID.");
            return null;
        }

        //System.out.println("OK. Response has same query ID.");
        int QR = (responseBuffer[2] & 0x80) >>> 7; // get 1st bit
        int opCode = (responseBuffer[2] & 0x78) >>> 3; // get 2nd, 3rd, 4th and 5th bit
        int AA = (responseBuffer[2] & 0x04) >>> 2; // geth 6th
        int TC = (responseBuffer[2] & 0x02) >>> 1; // get 7th bit
        int RD = responseBuffer[2] & 0x01; // get 8th bit
        if (QR != 1) {
            System.out.println("FAILED. Received datagram is not response");
            return null;
        }

        if (verboseTracing)
            System.out.println("Response ID: " + receivedQueryID + " Authoritative = " + (AA == 1));

        //System.out.println("OK. Received datagram is response.");
        int RA = responseBuffer[3] & 0x80;
        int RCODE = responseBuffer[3] & 0x0F;
        String message = "";
        boolean process = false;
        switch (RCODE) {
            case 0: message = "OK. No error on RCODE";
                    process = true;
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
        if (!process) {
            System.out.println(message);
            //return null;
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
        receivedQNAME = receivedQNAME.substring(0, receivedQNAME.length() - 1);
        if (!node.getHostName().equals(receivedQNAME)) {
            System.out.println("FAILED. Received QNAME is different than sent hostname. Received: " + receivedQNAME);
            return null;
        }
        //System.out.println("OK. Received same QNAME with sent hostname.");
        int QTYPE = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
        //System.out.println("OK. Received QTYPE code is " + QTYPE + " Type is " + RecordType.getByCode(QTYPE));
        int QCLASS = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
        if (QCLASS == 1) {
            //System.out.println("OK. Received QCLASS code is " + QCLASS + " It's IN(ternet)");
        } else {
            System.out.println("FAILED. Received QCLASS code is " + QCLASS + " It's not IN(ternet)");
            return null;
        }

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
            record = decodeSingleRecord(responseBuffer, false);
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

        if (AA == 1){
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
            return authNameServers;
        }
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static InetAddress retrieveResultsFromServer(DNSNode node, InetAddress server) {
      int queryID = getNewUniqueQueryID();
      byte[] queryBuffer = encodeQuery(queryID, node);
      int timeOutCount = 0;
      int maxTimeOutCount = 2;
      while(timeOutCount < maxTimeOutCount) {
          if (verboseTracing) {
              System.out.print("\n\n");
              System.out.println("Query ID     " + queryID + " " + node.getHostName() + "  " + node.getType() + " --> " + server.getHostAddress());
          }

          //System.out.print("Encoded Query: ");
          //printBufferHexDump(queryBuffer);

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
              //System.out.print("Received Response: ");
              //printBufferHexDump(responseBuffer);
              ArrayList<ResourceRecord> authNameServers = decodeResponse(queryID, node, responseBuffer);
              if (authNameServers == null) {
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


    private static void printBufferHexDump(byte[] buffer) {
        for (int x = 0 ; x < buffer.length; x++) {
            System.out.print(String.format("%02x ", buffer[x]));
        }
        System.out.println();
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-4s %-10d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-4s %-10d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }

    /**
    * Returns a new and unique query ID
    */
    private static int getNewUniqueQueryID() {
      int next = random.nextInt(65536);
      for (int i = 0; i < totalQueryCount; i++){
          if (generatedQueryIDs[i] == next) {
              return getNewUniqueQueryID();
          }
      }
      generatedQueryIDs[totalQueryCount++] = next;
      //System.out.println("Generated unique ID is " + next);
      return next;
    }
}
