package chatfileARP;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;

public class ARPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    _ARP_MSG m_sHeader;
    
    private ArrayList<String[]> arpCacheTable = new ArrayList<String[]>();
    private ArrayList<String[]> proxyTable = new ArrayList<String[]>();
	
	public ARPLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		ResetHeader();
	}

	public void ResetHeader() {
		m_sHeader = new _ARP_MSG();
	}
	
	private class _ETHERNET_ADDR {
        private byte[] addr = new byte[6];

        public _ETHERNET_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;
            this.addr[4] = (byte) 0x00;
            this.addr[5] = (byte) 0x00;
        }
        public _ETHERNET_ADDR(byte[] newAddr) {
        	this.addr = newAddr;
        }
    }
	private class _IP_ADDR {
        private byte[] addr = new byte[4];

        public _IP_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;
        }
        public _IP_ADDR(byte[] newAddr) {
        	this.addr = newAddr;
        }
    }
    
    // Ethernet 헤더를 추상화한 클래스
    private class _ARP_MSG {
        byte[] arp_hardwareType;
        byte[] arp_protocolType;
        byte[] arp_hardwareAndProtocolSize;
        byte[] arp_operation;
        _ETHERNET_ADDR arp_senderEtherentAddress;
        _IP_ADDR arp_senderIPAddress;
        _ETHERNET_ADDR arp_targetEthernetAddress;
        _IP_ADDR arp_targetIPAddress;

        public _ARP_MSG() {
            this.arp_hardwareType = new byte[] {0x00, 0x01}; // Ethernet = 1
            this.arp_protocolType = new byte[] {0x08, 0x00}; // IP Protocol = 0x0800
            this.arp_hardwareAndProtocolSize = new byte[] {0x06, 0x04}; // Ethernet Size = 6byte, IP Size = 4byte
            this.arp_operation = new byte[2];
            this.arp_senderEtherentAddress = new _ETHERNET_ADDR();
            this.arp_senderIPAddress = new _IP_ADDR();
            this.arp_targetEthernetAddress = new _ETHERNET_ADDR();
            this.arp_targetIPAddress = new _IP_ADDR();
        }
    }
    
    // byte배열로부터 정보를 추출하는 함수
    private byte[] extractHardwareType(byte[] bytes) {
    	return new byte[] {bytes[0], bytes[1]};
    }
    private byte[] extractProtocolType(byte[] bytes) {
    	return new byte[] {bytes[2], bytes[3]};
    }
    private byte[] extractHardwareSize(byte[] bytes) {
    	return new byte[] {bytes[4]};
    }
    private byte[] extractProtocolSize(byte[] bytes) {
    	return new byte[] {bytes[5]};
    }
    private byte[] extractOperation(byte[] bytes) {
    	return new byte[] {bytes[6], bytes[7]};
    }
    private byte[] extractSenderMacAddress(byte[] bytes) {
    	return new byte[] {bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13]};
    }
    private byte[] extractSenderIpAddress(byte[] bytes) {
    	return new byte[] {bytes[14], bytes[15], bytes[16], bytes[17]};
    }
    private byte[] extractTargetMacAddress(byte[] bytes) {
    	return new byte[] {bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23]};
    }
    private byte[] extractTargetIpAddress(byte[] bytes) {
    	return new byte[] {bytes[24], bytes[25], bytes[26], bytes[27]};
    }
    
    public byte[] ObjToByte(_ARP_MSG Header) {
    	byte[] buf = new byte[28];
    	
    	for (int i = 0; i < 2; i++) {
    		buf[i] = Header.arp_hardwareType[i];
    	}
    	for (int i = 0; i < 2; i++) {
    		buf[i+2] = Header.arp_protocolType[i];
    	}
    	for (int i = 0; i < 2; i++) {
    		buf[i+4] = Header.arp_hardwareAndProtocolSize[i];
    	}
    	for (int i = 0; i < 2; i++) {
    		buf[i+6] = Header.arp_operation[i];
    	}
    	for (int i = 0; i < 6; i++) {
    		buf[i+8] = Header.arp_senderEtherentAddress.addr[i];
    	}
    	for (int i = 0; i < 4; i++) {
    		buf[i+14] = Header.arp_senderIPAddress.addr[i];
    	}
    	for (int i = 0; i < 6; i++) {
    		buf[i+18] = Header.arp_targetEthernetAddress.addr[i];
    	}
    	for (int i = 0; i < 4; i++) {
    		buf[i+24] = Header.arp_targetIPAddress.addr[i];
    	}
    	return buf;
	}
    
    public boolean SendARP(byte[] input, int length) {
    	// 사전조건 => ARP:senderIPAddress, ARP:senderEthernetAddress 설정됨
    	// input => target IP주소 or target HW주소
    	
    	if (length == 4) { // 일반 ARP요청
    		// ARP 요청 내용 구성
        	this.m_sHeader.arp_operation = new byte[] {0x00, 0x01}; // ARP:operation = 0x0001(ARP Request)
        	this.m_sHeader.arp_targetIPAddress = new _IP_ADDR(input); // ARP:targetIPAddress = 전달된 Target IP
        	byte[] arpByte =  this.ObjToByte(this.m_sHeader); // ARP 요청 내용을 byte배열에 저장
        	// ARP Cache Table 갱신
        	this.addCacheEntry(IPByteToString(input), "unknown", "Incomplete");
        	// ARP 요청 전송
        	return this.GetUnderLayer().SendARP(arpByte, 28);
    	} else if (length == 6) { // Gratuitous ARP요청
    		// ARP 요청 내용 구성
        	this.m_sHeader.arp_operation = new byte[] {0x00, 0x01}; // ARP:operation = 0x0001(ARP Request)
        	this.m_sHeader.arp_targetIPAddress = this.m_sHeader.arp_senderIPAddress; // ARP:targetIPAddress 본인의 IP
        	byte[] arpByte =  this.ObjToByte(this.m_sHeader); // ARP 요청 내용을 byte배열에 저장
        	// ARP 요청 전송
        	return this.GetUnderLayer().SendARP(arpByte, 28);
    	}
    	
    	return false;
    }
    public boolean Receive(byte[] input) {
    	if (isArpReply(input)) { // 요청에 대한 응답이라면
    		this.completeCacheEntry(this.extractSenderIpAddress(input), this.extractSenderMacAddress(input));
    	} else { // 응답 이외의 경우(요청)
    		this.updateCacheEntry(this.extractSenderIpAddress(input), this.extractSenderMacAddress(input)); // Gratuitous ARP요청 수용
    		// ARP 요청에 응답해야하는지 판단
    		byte[] targetHardwareAddr = targetIsMe(input);
    		if (targetHardwareAddr == null) {
        		return false;
        	}
    		
    		// 요청에 응답해야한다면...
        	this.writeTargetHardwareAddress(input, targetHardwareAddr); // input:targetEtherentAddress에 하드웨어 주소 기입
        	this.swapTarget(input); // input:sender영역과 input:target영역을 스왑 
        	this.changeToReply(input); // input:operation을 응답(0x0002)으로 수정
        	return this.GetUnderLayer().SendARP(input, 28);
    	}
    	
    	return true;
    }
    private byte[] targetIsMe(byte[] bytes) {
    	// ARP 요청의 Target이 나인가?
    	boolean result = true;
    	for(int i = 0; i < 4; i++) {
    		if (this.m_sHeader.arp_senderIPAddress.addr[i] != bytes[i+24]) {
				result = false;
				break;
			}
    	}
    	
    	if (result) {
    		return this.m_sHeader.arp_senderEtherentAddress.addr;
    	}
    	
    	// ARP 요청의 Target이 내가 Proxy해주는 호스트들인가?
    	for(String[] anEntry : this.proxyTable) {
    		result = true;
    		byte[] comp = this.IPStringToByte(anEntry[0]);
    		for(int i = 0; i < 4; i++) {
    			if (comp[i] != bytes[i+24]) {
    				result = false;
    				break;
    			}
    		}
    		
    		if(result) {
    			return this.MacStringToByte(anEntry[1]);
    		}
    	}
    	
		return null;
    }
    private boolean isExpectedTarget(byte[] bytes) {
    	for(int i = 0; i < 6; i++) {
    		if (bytes[i+14] != this.m_sHeader.arp_targetIPAddress.addr[i])
    			return false;
    	}
    	return true;
    }
    private boolean isArpReply(byte[] bytes) {
    	// 해당 bytes가 ARP응답인지 확인
    	return bytes[6] == (byte) 0x00 && bytes[7] == (byte) 0x02;
    }
    private void writeTargetHardwareAddress(byte[] bytes, byte[] newTargetAddress) {
    	for(int i = 0; i < 6; i++) {
    		bytes[i+18] = newTargetAddress[i];
    	}
    }
    private void swapTarget(byte[] bytes) {
    	// 하드웨어 주소 SWAP
    	for(int i = 0; i < 6; i++) {
    		byte tempByte = bytes[i+8];
    		bytes[i+8] = bytes[i+18];
    		bytes[i+18] = tempByte;
    	}
    	// 프로토콜 주소 SWAP
    	for(int i = 0; i < 4; i++) {
    		byte tempByte = bytes[i+14];
    		bytes[i+14] = bytes[i+24];
    		bytes[i+24] = tempByte;
    	}
    }
    private void changeToReply(byte[] bytes) {
    	// bytes를 ARP응답으로 전환
    	bytes[6] = (byte) 0x00;
    	bytes[7] = (byte) 0x02;
    }
    
    // 주소 바이트<->문자열 변환 함수들
    private String MacByteToString(byte[] mac) {
	   String result = "";
	   int num[] = new int[6];
	   for(int i=0 ;i<mac.length;i++) {
	      num[i] = ((int)mac[i]) & 0xff ;
	      
	   }
	 
	   for(int i=0;i<num.length;i++) {
		   if(Integer.toHexString(num[i]).length() == 1) {
			   result += "0";
		   }
		   result += Integer.toHexString(num[i]);
		   if(i !=num.length-1) {
		      result +=":";
		   }   
	   }
	    
	    result = result.toUpperCase();
	    return result;
	 }
	private byte[] MacStringToByte(String mac) {
	   String[]str=  mac.split(":");
	   int []s = new int[6];  
	   for(int i=0;i<6;i++) {
	      s[i] = Integer.parseInt(str[i], 16);
	   }
	   byte macbyte[] = new byte[6];
	   for(int i=0;i<s.length;i++) {
	      macbyte[i] = (byte)s[i];
	   }
	   return macbyte;
	 }
	private String IPByteToString(byte[] ip) {
	   String result = "";
	   int num[] = new int[4];
	   for(int i=0 ;i<ip.length;i++) {
	      num[i] = (int)ip[i] & 0xff ;
	   }
	 
	   for(int i=0;i<num.length;i++) {
	      result += num[i];
	      if(i !=num.length-1) {
	         result +=".";
	      }   
	   }
	   return result;
	 }
	private byte[] IPStringToByte(String ip) {
		String[]str=  ip.split("\\.");
		int[] s = new int[4];  
		for(int i=0;i<4;i++) {
		   s[i] = Integer.parseInt(str[i]);
		}
		byte macbyte[] = new byte[4];
		for(int i=0;i<s.length;i++) {
		   macbyte[i] = (byte)s[i];
		}
		return macbyte;
 	}
	
	
	
	private String[] findTargetCacheEntry(byte[] ipAddress) {
		// 해당 IP를 갖는 entry가 Cache테이블에 존재하는지 탐색
		for (String[] anEntry : this.arpCacheTable) {
			if(anEntry[0].equals(this.IPByteToString(ipAddress)))
				return anEntry;
		}
		return null;
	}
	private String[] findTargetProxyEntry(byte[] ipAddress) {
		for (String[] anEntry : this.proxyTable) {
			if(anEntry[0].equals(this.IPByteToString(ipAddress)))
				return anEntry;
		}
		return null;
	}
	private String getNowDateTimeString() {
		return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
	}
	
	public ArrayList<String[]> getArpTableGUIContent() {
		ArrayList<String[]> content = new ArrayList<String[]>();
		for(String[] anEntry: this.arpCacheTable) {
			content.add(new String[] {anEntry[0], anEntry[1], anEntry[2]});
		}
		
		return content;
	}
	public ArrayList<String[]> getProxyTableGUIContent() {
		ArrayList<String[]> content = new ArrayList<String[]>();
		for(String[] anEntry: this.proxyTable) {
			content.add(new String[] {anEntry[0], anEntry[1], anEntry[2]});
		}
		
		return content;
	}
	
	private class ParameterTimerTask extends TimerTask {
		private ArrayList<String[]> targetTable;
		private String[] targetEntry;
		private String type;
		
		ParameterTimerTask(ArrayList<String[]> targetTable, String[] targetEntry, String type) {
			this.targetTable = targetTable;
			this.targetEntry = targetEntry;
			this.type = type;
		}
		
		@Override
		public void run() {
			if (this.type.equals("responseWaiting")) {
				if (targetEntry[2].equals("Incomplete")) {
					this.targetTable.remove(targetEntry);
					((ChatFileDlg) GetUpperLayer(0)).updateCacheTableGUI(getArpTableGUIContent());
				}
			} else if (this.type.equals("cacheDue")) {
				this.targetTable.remove(targetEntry);
				((ChatFileDlg) GetUpperLayer(0)).updateCacheTableGUI(getArpTableGUIContent());
			}
		}
	}
	
	private boolean addCacheEntry(String ipAddr, String macAddr, String status) {
		// 전달된 정보를 바탕으로 Cache테이블에 추가
		String[] newEntry = new String[] {ipAddr, macAddr, status};
		boolean result = this.arpCacheTable.add(newEntry);
		// 응답이 일정 시간 없을 경우 삭제
		Timer timer = new Timer();
		TimerTask task = new ParameterTimerTask(this.arpCacheTable, newEntry, "responseWaiting");
		timer.schedule(task, 30000);
		
		((ChatFileDlg) this.GetUpperLayer(0)).updateCacheTableGUI(this.getArpTableGUIContent());
    	return result;
	}
	private void completeCacheEntry(byte[] ipAddress, byte[] macAddress) {
		// 전달된 정보를 갖는 entry를 complete로 전환
		String[] targetEntry = this.findTargetCacheEntry(ipAddress);
		if(targetEntry != null && targetEntry[2].equals("Incomplete")) {
			targetEntry[1] = this.MacByteToString(macAddress);
			targetEntry[2] = "Complete";
		}
		// 일정 시간 동안 entry 유지
		Timer timer = new Timer();
		TimerTask task = new ParameterTimerTask(this.arpCacheTable, targetEntry, "cacheDue");
		timer.schedule(task, 60000);
		
		((ChatFileDlg) this.GetUpperLayer(0)).updateCacheTableGUI(this.getArpTableGUIContent());
	}
	private void updateCacheEntry(byte[] ipAddress, byte[] macAddress) {
		// Gratuitous ARP요청이 들어오면 호출
		String[] targetEntry = findTargetCacheEntry(ipAddress);
		if(targetEntry != null) {
			targetEntry[1] = this.MacByteToString(macAddress);
			targetEntry[2] = "Complete";
		}
		
		((ChatFileDlg) this.GetUpperLayer(0)).updateCacheTableGUI(this.getArpTableGUIContent());
	}
	public boolean deleteCacheEntry(int targetIndex) {
		// 해당 index의 entry 삭제
		String[] removedEntry = null;
		try {
			removedEntry = this.arpCacheTable.remove(targetIndex);
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		if(removedEntry != null) {
			return true;
		} else {
			return false;
		}
	}
	public void deleteAllCacheEntry() {
		this.arpCacheTable.clear();
	}
	
	public boolean addProxyEntry(String name, String ipAddress, String macAddress) {
		// 전달된 정보를 바탕으로 Proxy테이블에 entry 추가
		boolean result =  this.proxyTable.add(new String[] {name, ipAddress, macAddress});
		return result;
	}
	public boolean deleteProxyEntry(int targetIndex) {
		// 해당 index의 entry 삭제
		String[] removedEntry = null;
		try {
			removedEntry = this.proxyTable.remove(targetIndex);
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		if(removedEntry != null) {
			return true;
		} else {
			return false;
		}
	}
	
	public byte[] getTargetHardwareAddress(byte[] targetIP) {
		String[] targetEntry = this.findTargetCacheEntry(targetIP);
		if(targetEntry == null)
			return null;
		else
			return this.MacStringToByte(targetEntry[1]);
	}
    
    
	public void SetHardwareSenderAddress(byte[] senderAddress) {
		// TODO Auto-generated method stub
		m_sHeader.arp_senderEtherentAddress.addr = senderAddress;
	}

	public void SetHardwareTargetAddress(byte[] targetAddress) {
		// TODO Auto-generated method stub
		m_sHeader.arp_targetEthernetAddress.addr = targetAddress; 
	}
	public void SetProtocolSenderAddress(byte[] senderAddress) {
		// TODO Auto-generated method stub
		m_sHeader.arp_senderIPAddress.addr = senderAddress;
	}

	public void SetProtocolTargetAddress(byte[] targetAddress) {
		// TODO Auto-generated method stub
		m_sHeader.arp_targetIPAddress.addr = targetAddress;
	}
    
    @Override
    public String GetLayerName() {
        // TODO Auto-generated method stub
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        // TODO Auto-generated method stub
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        // TODO Auto-generated method stub
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        // TODO Auto-generated method stub
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }
}
