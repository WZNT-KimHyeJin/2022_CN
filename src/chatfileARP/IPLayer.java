package chatfileARP;

import java.util.ArrayList;

public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    _IP_HEADER m_sHeader;
	
	public IPLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		ResetHeader();
	}
	
	public void ResetHeader() {
		m_sHeader = new _IP_HEADER();
	}
	
	// IP 주소를 추상화한 클래스
    private class _IP_ADDR {
        private byte[] addr = new byte[4];

        public _IP_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
            this.addr[2] = (byte) 0x00;
            this.addr[3] = (byte) 0x00;

        }
    }
    
    // IP 헤더를 추상화한 클래스
    // 주소(근원지, 목적지) 필드만 사용할 것
    private class _IP_HEADER {
    	byte[] ip_versionAndLen; // IP버전
    	byte[] ip_tos; // type of service
    	byte[] ip_len; // 패킷 총 길이
    	byte[] ip_id; // 데이터그램 ID
    	byte[] ip_fragOffset; // Fragment 변위
    	byte[] ip_ttlAndProtocol; // Time To Live & Protocol Type
    	byte[] ip_cksum; // CheckSum
    	_IP_ADDR ip_srcAddr; // 근원지 IP주소
    	_IP_ADDR ip_dstAddr; // 목적지 IP주소

        public _IP_HEADER() {
            this.ip_versionAndLen = new byte[] {0x40}; // IP버전 = IPv4
            this.ip_tos = new byte[1];
            this.ip_len = new byte[2];
            this.ip_id = new byte[2];
            this.ip_fragOffset = new byte[2];
            this.ip_ttlAndProtocol = new byte[] {0x00, 0x06}; // Protocol Type = IP Protocol
            this.ip_cksum = new byte[2];
            this.ip_srcAddr = new _IP_ADDR();
            this.ip_dstAddr = new _IP_ADDR();
        }
    }
    
    public int IPHEADERLENGTH=20;
    
    // - Header에 저장된 필드들을 순서에 맞게 byte배열에 복사
    // - input에 저장된 필드들을 순서에 맞게 byte배열에 복사
    public byte[] ObjToByte(_IP_HEADER Header, byte[] input, int length) {//data에 헤더 붙여주기
       byte[] buf = new byte[length + IPHEADERLENGTH];
               
      buf[0] =Header.ip_versionAndLen[0];
      buf[1] = Header.ip_tos[0];
      for(int i=0;i<2;i++) {
         buf[2+i] = Header.ip_len[i];
         buf[4+i] = Header.ip_id[i];
         buf[6+i] = Header.ip_fragOffset[i];
         buf[10+i] = Header.ip_cksum[i];
               
      }
      buf[8] = Header.ip_ttlAndProtocol[0];
      buf[9] = Header.ip_ttlAndProtocol[1];
            
       for(int i = 0; i < 4; i++) {
         buf[12+i] = Header.ip_srcAddr.addr[i];
         buf[16+i] = Header.ip_dstAddr.addr[i];
      }
       
      for (int i = 0; i < length; i++)
         buf[IPHEADERLENGTH+i] = input[i];

      return buf;
   }
    
    
    public boolean Send(byte[] input, int length) {

      byte[] bytes = ObjToByte(m_sHeader, input, length);
      return this.GetUnderLayer().Send(bytes, length + IPHEADERLENGTH);
    }
    
    
    public boolean Receive(byte[] input) {
       byte[] data;

      if (isMyPacket(input)) { // 내가 보낸 패킷인가?
         return false;
      }else {
         if(chkAddr(input)) {
            data = RemoveEthernetHeader(input, input.length);
            return this.GetUpperLayer(0).Receive(data);
         }
      }
      
       return false;
    }
    
   private boolean isMyPacket(byte[] input){
      for(int i = 0; i < 4; i++)
         if(m_sHeader.ip_srcAddr.addr[i] != input[12 + i])
            return false;
      return true;
   }
   
   private boolean chkAddr(byte[] input) {
      for(int i = 0; i< 4; i++)
         if(m_sHeader.ip_srcAddr.addr[i] != input[16+i])
            return false;
      return true;
   }
   private byte[] RemoveEthernetHeader(byte[] input, int length) {
      byte[] cpyInput = new byte[length - IPHEADERLENGTH];
      System.arraycopy(input, IPHEADERLENGTH, cpyInput, 0, length - IPHEADERLENGTH);
      input = cpyInput;
      return input;
   }

    
    /*
    public boolean ARPRequest(byte[] targetIPAddress, String type) {
    	return ((IPLayer) this.GetUnderLayer()).ARPRequest(targetIPAddress, type);
    }
    */
    
    public void SetIPSrcAddress(byte[] srcAddress) {
		// TODO Auto-generated method stub
		m_sHeader.ip_srcAddr.addr = srcAddress;
	}

	public void SetIPDstAddress(byte[] dstAddress) {
		// TODO Auto-generated method stub
		m_sHeader.ip_dstAddr.addr = dstAddress;
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
