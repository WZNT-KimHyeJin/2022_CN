package chatfileARP;

import java.util.ArrayList;

public class EthernetLayer implements BaseLayer {
	
	// 상위 레이어에서 계층을 생성하여 초기화
	// 필드만 만들어놓으면됨
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	_ETHERNET_Frame m_sHeader;
	
	public EthernetLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		ResetHeader();
	}
	
	public void ResetHeader() {
		m_sHeader = new _ETHERNET_Frame();
	}
	
	// Ethernet 주소(MAC주소)를 추상화한 클래스
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
    }
    
    // Ethernet 프레임를 추상화한 클래스
    private class _ETHERNET_Frame {
        _ETHERNET_ADDR enet_dstaddr; // 목적지 주소
        _ETHERNET_ADDR enet_srcaddr; // 근원지 주소
        byte[] enet_type; // 타입
        byte[] enet_data; // 데이터(여기서는 사용을 안함)

        public _ETHERNET_Frame() {
            this.enet_dstaddr = new _ETHERNET_ADDR();
            this.enet_srcaddr = new _ETHERNET_ADDR();
            this.enet_type = new byte[2];
            this.enet_data = null;
        }
    }
    
    
    public byte[] ObjToByte(_ETHERNET_Frame Header, byte[] input, int length) {//data에 헤더 붙여주기
		byte[] buf = new byte[length + 14];
		for(int i = 0; i < 6; i++) {
			buf[i] = Header.enet_dstaddr.addr[i];
			buf[i+6] = Header.enet_srcaddr.addr[i];
		}			
		buf[12] = Header.enet_type[0];
		buf[13] = Header.enet_type[1];
		for (int i = 0; i < length; i++)
			buf[14 + i] = input[i];
		

		return buf;
	}
    
    // 텍스트 전송
    public boolean Send(byte[] input, int length) {
    	this.m_sHeader.enet_type = new byte[] {0x08, 0x00};
    	byte[] bytes = ObjToByte(m_sHeader, input, length);
    	return this.GetUnderLayer().Send(bytes, length + 14);
   }
    
    public boolean SendARP(byte[] input, int length) {
    	this.m_sHeader.enet_type = new byte[] {0x00, 0x00};
    	this.m_sHeader.enet_dstaddr.addr = new byte[] {(byte) 0xff, (byte) 0xff,(byte) 0xff,(byte) 0xff,(byte) 0xff,(byte) 0xff};
    	byte[] bytes = ObjToByte(m_sHeader, input, length);
    	return this.GetUnderLayer().Send(bytes, length + 14);
    }

	private byte[] RemoveEthernetHeader(byte[] input, int length) {
		// 전달받은 데이터(프레임)에서 EthernetHeader(14byte) 제거
		byte[] cpyInput = new byte[length - 14];
		System.arraycopy(input, 14, cpyInput, 0, length - 14);
		input = cpyInput;
		return input;
	}
	
	public boolean Receive(byte[] input) {
		// EthernetHeader 구조(실습자료 참고)
      // input[0] ~ input[5] => 목적지(destination) MAC주소
      // input[6] ~ input[11] => 근원지(source) MAC 주소
      // input[12] ~ input[13] => 타입
      // input[14] ~ => 상위 계층 데이터
      
      byte[] data;
      
      if (isMyPacket(input)) { // 내가 보낸 패킷인가?
         // 내가 보낸 패킷이면 버린다
         return false;
      } else {
         // 내가 보낸 패킷이 아니라면
         if (!isBroadcast(input)) { // 방송용 패킷인가?
            if (!chkAddr(input)) { // 나를 목적지로 하는 패킷인가?
               return false;
            }
         }
         data = this.RemoveEthernetHeader(input, input.length);
       if(input[12] == 0x08 && input[13] == 0x00) { //type이 IP인 경우
          return this.GetUpperLayer(1).Receive(data);
       }else if(input[12] == 0x00 && input[13] == 0x00) { //type이 ARP인 경우
          return this.GetUpperLayer(0).Receive(data);
       }
         // 방송용 패킷 => 수용
         // 나를 목적지로 하는 패킷 => 수용
      }
      return false;
	}
	
	private boolean isBroadcast(byte[] bytes) {
		for(int i = 0; i< 6; i++)
			if (bytes[i] != (byte) 0xff)
				return false;
		return true;
	}

	private boolean isMyPacket(byte[] input){
		for(int i = 0; i < 6; i++)
			if(m_sHeader.enet_srcaddr.addr[i] != input[6 + i])
				return false;
		return true;
	}

	private boolean chkAddr(byte[] input) {
		byte[] temp = m_sHeader.enet_srcaddr.addr;
		for(int i = 0; i< 6; i++)
			if(m_sHeader.enet_srcaddr.addr[i] != input[i])
				return false;
		return true;
	}
	
	public void SetEnetSrcAddress(byte[] srcAddress) {
		// TODO Auto-generated method stub
		m_sHeader.enet_srcaddr.addr = srcAddress;
	}

	public void SetEnetDstAddress(byte[] dstAddress) {
		// TODO Auto-generated method stub
		m_sHeader.enet_dstaddr.addr = dstAddress;
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
