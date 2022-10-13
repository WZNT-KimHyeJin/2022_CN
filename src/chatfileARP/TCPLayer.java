package chatfileARP;

import java.util.ArrayList;

public class TCPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    _TCP_HEADER m_sHeader;
	
	public TCPLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		ResetHeader();
	}
	
	public void ResetHeader() {
		m_sHeader = new _TCP_HEADER();
	}
	
	// TCP Port주소를 추상화한 클래스
    private class _PORT_ADDR {
        private byte[] addr = new byte[2];

        public _PORT_ADDR() {
            this.addr[0] = (byte) 0x00;
            this.addr[1] = (byte) 0x00;
        }
    }
    
    // TCP 헤더를 추상화한 클래스
    // 다른 곳에서는 내부 클래스에 Header+데이터 형식으로 자료형을 정의
    // 하지만 데이터 부분을 사용하지 않으므로 여기서는 제외하였음
    private class _TCP_HEADER {
    	// TCP 표준 헤더의 형식을 갖추고있음
    	// 하지만 우리는 주소(근원지, 목적지)만 사용하고 다른 필드들은 사용하지 않을 것
    	_PORT_ADDR port_srcAddr; // 근원지 주소
    	_PORT_ADDR port_dstAddr; // 목적지 주소
        byte[] tcp_seq; // sequence number
        byte[] tcp_ack; // ack sequence number
        byte[] tcp_offsetAndFlag; // offset & control flag
        byte[] tcp_window;
        byte[] tcp_cksum; // check sum
        byte[] tcp_urgptr;
        byte[] tcp_padding;
        // byte[] tcp_data; -> 데이터
        
        public _TCP_HEADER() {
        	this.port_srcAddr = new _PORT_ADDR();
            this.port_dstAddr = new _PORT_ADDR();
            this.tcp_seq = new byte[4];
            this.tcp_ack = new byte[4];
            this.tcp_offsetAndFlag = new byte[2];
            this.tcp_window = new byte[2];
            this.tcp_cksum = new byte[2];
            this.tcp_urgptr =  new byte[2];
            this.tcp_padding = new byte[4];
        }
    }
    
    int TCPHEADERLENGTH = 24;
    
    public byte[] ObjToByte(_TCP_HEADER Header, byte[] input, int length) {//data에 헤더 붙여주기
        byte[] buf = new byte[length + TCPHEADERLENGTH];
        for(int i = 0; i < 2; i++) {
           buf[i] = Header.port_dstAddr.addr[i];
           buf[i+2] = Header.port_srcAddr.addr[i];
        }
        for(int i = 0; i < length; i++) {
           buf[24 + i] = input[i];
        }
        return buf;
     }
      
      // 헤더를 제거하는 메소드, 데이터 부분만 남김
    public byte[] RemoveHeader(byte[] input, int length) {
	     byte[] removedHeader = new byte[length - TCPHEADERLENGTH];
	     
	     for(int i = 0; i < length - TCPHEADERLENGTH; i++) {
	        removedHeader[i] = input[TCPHEADERLENGTH + i];
	     }
	     return removedHeader;
	  }
  
    //헤더와 데이터를 이어서 만든 프레임을 하위레이어로 전송함
    public boolean Send(byte[] input, int length) {
    	m_sHeader.port_dstAddr.addr[0] = (byte) 0x20;
    	m_sHeader.port_dstAddr.addr[1] = (byte) 0x80;
    	m_sHeader.port_srcAddr.addr[0] = (byte) 0x20;
    	m_sHeader.port_srcAddr.addr[1] = (byte) 0x80;
       
    	byte[] data = ObjToByte(m_sHeader, input, length);
    	this.GetUnderLayer().Send(data, length + TCPHEADERLENGTH);
    	return true;
    }
    // 파일 전송
    public void fileSend(byte[] input, int length) {
    	m_sHeader.port_dstAddr.addr[0] = (byte) 0x20;
    	m_sHeader.port_dstAddr.addr[1] = (byte) 0x90;
    	m_sHeader.port_srcAddr.addr[0] = (byte) 0x20;
    	m_sHeader.port_srcAddr.addr[1] = (byte) 0x90;
       
    	byte[] bytes = ObjToByte(m_sHeader, input, length);
    	this.GetUnderLayer().Send(bytes, length + TCPHEADERLENGTH);
    }
    //수신자임을 확인하고 맞으면 헤더를 떼어내고 데이터를 상위 레이어로 전달함
    public boolean Receive(byte[] input) {
    	byte[] data;

     //포트번호가 자신의 것이 아니면 버린다
    	for(int i = 0; i < 2; i++) {
    		if(input[i] != m_sHeader.port_dstAddr.addr[i] 
              || input[i+2] != m_sHeader.port_srcAddr.addr[i]) {
    			return false;
    		}
    	}
     
    	if (m_sHeader.port_dstAddr.addr[0] == 0x20 && m_sHeader.port_dstAddr.addr[1] == 0x80) { // 텍스트(ChatAppLayer)
    		data = RemoveHeader(input, input.length); // Header 제거
    		this.GetUpperLayer(0).Receive(data);
    		return true;
    	} else if (m_sHeader.port_dstAddr.addr[0] == 0x20 && m_sHeader.port_dstAddr.addr[1] == 0x90) { // 파일(FileAppLayer)
    		data = RemoveHeader(input, input.length); // Header 제거
    		this.GetUpperLayer(1).Receive(data);
    		return true;
    	}
    	return false;
    }
    
    /*
    public boolean ARPRequest(byte[] targetIPAddress, String type) {
    	return ((IPLayer) this.GetUnderLayer()).ARPRequest(targetIPAddress, type);
    }
    */
    
    
    public void SetPortSrcAddress(byte[] srcAddress) {
		// TODO Auto-generated method stub
		m_sHeader.port_srcAddr.addr = srcAddress;
	}

	public void SetPortDstAddress(byte[] dstAddress) {
		// TODO Auto-generated method stub
		m_sHeader.port_srcAddr.addr = dstAddress;
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
