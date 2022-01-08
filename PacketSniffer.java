import java.io.*;
import java.util.*;

public class Assignment1{
	public static void main(String[] args) throws IOException {
			String fileName = "new_tcp_packet1.bin";
			initProcessing(fileName);
			
	}

	public static void initProcessing(String filename) throws IOException {
		try (InputStream in = new FileInputStream(filename)) {
			List<Integer> data = new ArrayList<Integer>();
			byte bytes;
			int totalLen = in.available();
			while((bytes = (byte) in.read()) != -1) {	
				data.add(Byte.toUnsignedInt(bytes));
			}
			in.close();
			Ethernet ether = new Ethernet(data, totalLen);
			ether.printEtherHeader();
		}
		
		
	}
	
	public String toHex(Integer a) {
		return String.format("%02X", a);
	}
	
}


class Ethernet{
	List<Integer> data;
	Assignment1 obj;
	boolean hasIP;
	int headerLen;
	public Ethernet(List<Integer> data, int headerLen) {
		this.data = data;
		obj = new Assignment1();
		hasIP = false;
		this.headerLen = headerLen;
	}

	public void printEtherHeader() {
		System.out.println("ETHER:   ----- Ether Header -----");
		System.out.println("ETHER: \nETHER:   Packet size = "+headerLen + " bytes");
		String destination = "";
		String source = "";
		String type = "";
		for(int i=0; i<6; i++) {
			destination += obj.toHex(data.get(i));
			if(i != 5) {
				destination += ":";
			}
		}
		for(int i=6; i<12; i++) {
			source += obj.toHex(data.get(i));
			if(i != 11) {
				source += ":";
			}
		}
		for(int i=12; i<14; i++) {
			type += obj.toHex(data.get(i));
		}
		if(type.equals("0800")) {
			type += " (IPv4)";
			hasIP = true;
		}
		
		System.out.println("ETHER:   Destination = "+ destination);
		System.out.println("ETHER:   Source      = "+ source);
		System.out.println("ETHER:   Ethertype   = "+ type + "\nETHER:");
		
		if(true) {
			IP p = new IP(data, 14);
			p.printIPHeader();
		}
	}
	
	
}

class IP{
	List<Integer> data;
	int startByteIndex;
	int scale;
	Assignment1 obj;
	String nextProtocol;
	boolean options;
	int headerLength;
	
	public IP(List<Integer> data, int startIndex) {
		this.data = data;
		startByteIndex = startIndex;
		obj = new Assignment1();
		scale = 0;
		nextProtocol = "";
		
	}
	
	public void printIPHeader() {
		System.out.println("IP:      ----- IP Header ----- \nIP:");
		printVersion();
		printHeaderLength();
		printDSCP();
		printTotalLength();
		printIdentifier();
		printFlags();
		printFragmentOffset();
		printTTL();
		printProtocol();
		printCheckSum();
		printSourceAddress();
		printDestAddress();
		printOptions();
		finalProtocol();
	}
	
	private void printVersion() {		
		int version = (data.get(startByteIndex)/16);
		System.out.println("IP:      Version = "+version );
	}
	
	private void printHeaderLength() {
		this.headerLength = (data.get(startByteIndex)%16)<<2;
		System.out.println("IP:      Header Length = "+ this.headerLength + " bytes");
		scale = 1;
	}
	
	private void printDSCP() {
		int dscpVal = data.get(startByteIndex+scale);
		System.out.println("IP:      DSCP = 0x"+obj.toHex(dscpVal));
		scale++;
	}
	
	private void printTotalLength() {
		int length = (data.get(startByteIndex+scale)<<8) | ((data.get(startByteIndex+scale+1)));
		System.out.println("IP:      Total length = "+ length+ " bytes");
		scale += 2;
	}
	
	private void printIdentifier() {
		int i=startByteIndex+scale;
		int temp = data.get(i) << 8;
		int identifier = temp | data.get(i+1);
		System.out.println("IP:      Identifier = "+ identifier);
		scale+=2;
	}
	
	private void printFlags() {
		int i = startByteIndex + scale;
		int flag = 0;
		String f1 = "";
		String f2 = "";
		String f3 = "";
		if(((1<<7)&data.get(i)) == 0) {
			f1 = "IP:         .0.. ...... = reserved bit, always 0";
			flag += Math.pow(2, 3)*0;
		}
		int getDoNotFragment = 1<<6;
		if( (getDoNotFragment & data.get(i)) != 0 ) {
			f2 = "IP:         ..1.. ...... = Do not fragment";
			flag += Math.pow(2, 2)*1;
		}else {
			f2 = "IP:         ..0.. ...... = Do fragmentation";
		}
		
		int moreFragments = (1<<5);
		if((moreFragments & data.get(i)) != 0 ) {
			f3 = "IP:         ...1.. ...... = more fragments left";
			flag += Math.pow(2, 1)*1;
		} else {
			f3 = "IP:         ...0.. ...... = last fragment";
			}
		System.out.println("IP:      Flags = 0x"+obj.toHex(flag) + "\n" + f1 + "\n" +f2 +"\n" + f3);

	}
	
	private void printFragmentOffset() {
		int i = startByteIndex+scale;
		int temp = data.get(i) & 31;
		int fragmentOffset = temp | data.get(i+1);
		System.out.println("IP:      Fragment offset = "+fragmentOffset + " bytes");
		scale += 2;
	}
	
	private void printTTL() {
		System.out.println("IP:      Time to live = "+ data.get(startByteIndex + scale) + " seconds/hops");
		scale++;
	}
	
	private void printProtocol() {
		int protocol = data.get(startByteIndex+scale);
		if(protocol == 1) {
			nextProtocol = "ICMP";
		}
		else if(protocol == 6) {
			nextProtocol = "TCP";
		}
		else if(protocol == 17) {
			nextProtocol = "UDP";
		}
		else {
			nextProtocol = "NONE";
		}
		System.out.println("IP:      Protocol = "+ protocol + " (" + nextProtocol + ")");
		
		scale++;
	}
	
	private void printCheckSum() {
		int i = startByteIndex + scale;
		System.out.println("IP:      Check sum = 0x" + obj.toHex(data.get(i)) + "" + obj.toHex(data.get(i+1)));
		scale += 2;
	}
	
	private void printSourceAddress() {
		int i = startByteIndex + scale;
		int first = data.get(i);
		int second = data.get(i+1);
		int third = data.get(i+2);
		int fourth = data.get(i+3);
		System.out.println("IP:      Source address = " + first + "." + second + "." + third + "." + fourth);
		scale += 4;
	}
	
	private void printDestAddress() {
		int i = startByteIndex + scale;
		int first = data.get(i);
		int second = data.get(i+1);
		int third = data.get(i+2);
		int fourth = data.get(i+3);
		System.out.println("IP:      Destination address = " + first + "." + second + "." + third + "." + fourth);
		scale += 4;
	}
	
	private void printOptions() {
		if(options) {
			int i = startByteIndex + scale;
			String optionVal = "";
			int optionalBytes =  this.headerLength - 20; 
			for(int j=0; j<optionalBytes; j++) {
				optionVal += obj.toHex(data.get(j+i))+" ";
			}
			System.out.println("IP:      Options = "+optionVal);
			scale += optionalBytes;
		}else {
			System.out.println("IP:      No options");
		}
	}
	
	private void finalProtocol() {
		System.out.println("IP:");
		if(nextProtocol == "ICMP") {
			ICMP p = new ICMP(data, startByteIndex+scale);	
			p.printHeader();
		}
		if(nextProtocol == "TCP") {
			TCP p = new TCP(data, startByteIndex+scale);
			p.printHeader();
		}
		if(nextProtocol == "UDP") {
			UDP p = new UDP(data, startByteIndex+scale);
			p.printHeader();
		}
		
	}
	
}

class ICMP{
	int startInd;
	List<Integer> data;
	int scale;
	Assignment1 obj;
	ICMP(List<Integer> data, int startInd){
		this.startInd = startInd;
		this.data = data;
		scale = 0;
		obj = new Assignment1();
	}
	public void printHeader() {
		System.out.println("ICMP:      ----- ICMP Header ----- \nICMP:");
		printType();
		printCode();
		printCheckSum();
		System.out.println("ICMP:");
	}
	
	private void printType() {
		System.out.println("ICMP:      Type = " + data.get(startInd));
		scale += 1;
	}
	
	private void printCode() {
		System.out.println("ICMP:      Code = " + data.get(startInd+1));
		scale += 1;
	}
	
	private void printCheckSum() {
		int i = startInd + scale;
		int part1 = data.get(i);
		int part2 = data.get(i+1);
		int checkSum = (part1<<8) | part2;
		System.out.println("ICMP:      Checksum = 0x"+obj.toHex(checkSum));
		scale += 2;
	}
	
}

class TCP {
	int startInd;
	List<Integer> data;
	int scale;
	Assignment1 obj;
	
	TCP(List<Integer> data, int startInd){
		this.startInd = startInd;
		this.data = data;
		scale = 0;
		obj = new Assignment1();
	}
	public void printHeader() {
		System.out.println("TCP:      ----- TCP Header ----- \nTCP:");
		printSourcePort();
		printDestPort();
		printSeqNum();
		printAckNum();
		printDataOffset();
		printFlags();
		printWindow();
		printCheckSum();
		printUrgentPtr();
		printOptions();
		printData();
	}
	
	private void  printSourcePort() {
		int i = startInd + scale;
		int first = (data.get(i)) << 8;
		int second = (data.get(i+1));
		int sourcePort = first | second;
		System.out.println("TCP:      Source port = "+sourcePort);
		scale += 2;
	}
	
	private void printDestPort() {
		int i = startInd + scale;
		int first = (data.get(i)) << 8;
		int second = (data.get(i+1));
		int destPort = first | second;
		System.out.println("TCP:      Destination port = "+destPort);
		scale += 2;
	}
	private void printSeqNum() {
		int i = startInd + scale;
		long first = (data.get(i)) << (8*3);
		long second = (data.get(i+1)) << (8*2);
		long third = (data.get(i+2)) << (8);
		long fourth = (data.get(i+3));
		long seqNum = first | second | third | fourth;
		System.out.println("TCP:      Sequence number = "+seqNum);
		scale += 4;
	}
	private void printAckNum() {
		int i = startInd + scale;
		long first =(data.get(i)) << 8*3;
		long second = (data.get(i+1)) << 8*2;
		long third = (data.get(i+2)) << 8;
		long fourth = (data.get(i+3));
		long ackNum = first | second | third | fourth;
		System.out.println("TCP:      Acknowledgement number = "+ ackNum + " (Printing in Two's complement)");
		scale += 4;
	}
	private void printDataOffset() {
		int i = startInd + scale;
		int dataOffset = (data.get(i)) / 16;
		System.out.println("TCP:      Data offset = "+dataOffset + " bytes" );
	}
	private void printFlags() {
		int  i = startInd + scale;
		int b = data.get(i+1);
		int flag;
		if( (data.get(i) & 1) == 1) {
			flag = (1<<8) | b;
		} else {
			flag = b;
		}
		System.out.println("TCP:      Flags = 0x"+obj.toHex(flag));
		scale += 2;
		if((b & 32) == 32) {
			System.out.println("TCP:      ..1..... = urgent pointer is set");
		} else {
			System.out.println("TCP:      ..0..... = No urgent pointer");
		}
		
		if( (b & 16) == 16 ) {
			System.out.println("TCP:      ...1..... = Acknowledgement field is significant");
		} else {
			System.out.println("TCP:      ...0..... = Acknowledgement field is not significant");
		}
		
		if((b &8) ==8) {
			System.out.println("TCP:      ....1..... = Push function is set");
		} else {
			System.out.println("TCP:      ....0..... = No push data");
		}
		
		if((b&4) == 4){
			System.out.println("TCP:      .....1..... = Reset is set");
		} else {
			System.out.println("TCP:      .....0..... = No reset");
		}
		
		if((b & 2) == 2){
			System.out.println("TCP:      ......1..... = Synchronise sequence numbers");
		} else {
			System.out.println("TCP:      ......0..... = Do not synchronise sequence numbers");
		}
		
		if((b&1) == 1) {
			System.out.println("TCP:      .......1..... = Fin is set");
		} else {
			System.out.println("TCP:      .......0..... = No Fin");
		}
	}
	
	private void printWindow() {
		int i = startInd + scale;
		int part1 = data.get(i);
		int part2 = data.get(i+1);
		int window = (part1<<8) | part2;
		System.out.println("TCP:      Window = "+window);
		scale += 2;
	}
	private void printCheckSum() {
		int i = startInd + scale;
		int part1 = data.get(i);
		int part2 = data.get(i+1);
		int checkSum = (part1<<8) | part2;
		System.out.println("TCP:      Checksum = 0x"+obj.toHex(checkSum));
		scale += 2;
	}
	private void printUrgentPtr() {
		int i = startInd + scale;
		int part1 = data.get(i);
		int part2 = data.get(i+1);
		int urgentPtr = (part1<<8) | part2;
		System.out.println("TCP:      Urgent pointer = "+urgentPtr);
		scale += 2;
	}
	private void printOptions() {
		System.out.println("TCP:      No options \nTCP:");
	}
	private void printData() {
		int i = startInd;
		System.out.println("TCP:      Data(first 32 bytes) =");
		String printD = "\t\t\t\t";
		for(int j = 0; j<32; j++) {
			printD += obj.toHex(data.get(j+i)) + "";
			if(j%2 == 1) {
				printD += " ";
			}
			if(j%16 == 1 && j!=1 ) {
				printD += "\n\t\t\t\t";
			}
		}
		System.out.println(printD);	
	}
	
}

class UDP{
	int startInd;
	int scale;
	List<Integer> data;
	Assignment1 obj; 
	UDP(List<Integer> data, int startInd){
		this.startInd = startInd;
		this.data = data;
		scale = 0;
		obj = new Assignment1();
	}
	public void printHeader() {
		System.out.println("UDP:      ----- UDP Header ----- \nUDP:");
		printSourcePort();
		printDestPort();
		printlLength();
		printCheckSum();
		printData();
	}
	
	private void  printSourcePort() {
		int i = startInd + scale;
		int first = (data.get(i)) << 8;
		int second = (data.get(i+1));
		int sourcePort = first | second;
		System.out.println("UDP:      Source port = "+sourcePort);
		scale += 2;
	}
	
	private void printDestPort() {
		int i = startInd + scale;
		int first = (data.get(i)) << 8;
		int second = (data.get(i+1));
		int destPort = first | second;
		System.out.println("UDP:      Destination port = "+destPort);
		scale += 2;
	}
	
	private void printlLength() {
		int length = (data.get(startInd+scale)<<8) | ((data.get(startInd+scale+1)));
		System.out.println("UDP:      Total length = "+ length);
		scale += 2;
	}
	
	private void printCheckSum() {
		int i = startInd + scale;
		int part1 = data.get(i);
		int part2 = data.get(i+1);
		int checkSum = (part1<<8) | part2;
		System.out.println("UDP:      Checksum = 0x"+obj.toHex(checkSum));
		scale += 2;
	}
	
	private void printData() {
		int i = startInd;
		System.out.println("UDP:      Data(first 32 bytes) =");
		String printD = "UDP:\t\t\t\t";
		for(int j = 0; j<32; j++) {
			printD += obj.toHex(data.get(j+i)) + "";
			if(j%2 == 1) {
				printD += " ";
			}
			if(j%16 == 1 && j!=1 ) {
				printD += "\nUDP:\t\t\t\t";
			}
		}
		System.out.println(printD);	
	}
	
	
}



