package chatfileARP;

import java.util.ArrayList;

public class ChatAppLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    _CHAT_APP m_sHeader;

    private byte[] fragBytes;
    private int fragCount = 0;
    private ArrayList<Boolean> ackChk = new ArrayList<Boolean>();

    private class _CHAT_APP {
        byte[] capp_totlen;
        byte capp_type;
        byte capp_unused;
        byte[] capp_data;

        public _CHAT_APP() {
            this.capp_totlen = new byte[2];
            this.capp_type = 0x00;
            this.capp_unused = 0x00;
            this.capp_data = null;
        }
    }

    public ChatAppLayer(String pName) {
        // super(pName);
        // TODO Auto-generated constructor stub
        pLayerName = pName;
        ResetHeader();
    }

    private void ResetHeader() {
        m_sHeader = new _CHAT_APP();
    }

    private byte[] objToByte(_CHAT_APP Header, byte[] input, int length) {
    	// 헤더 객체(_CHAT_APP)를 바이트 배열로 변환
        byte[] buf = new byte[length + 4];

        buf[0] = Header.capp_totlen[0];
        buf[1] = Header.capp_totlen[1];
        buf[2] = Header.capp_type;
        buf[3] = Header.capp_unused;

        if (length >= 0) System.arraycopy(input, 0, buf, 4, length);

        return buf;
    }

    public byte[] RemoveCappHeader(byte[] input, int length) {
    	// 전달된 input배열에서 헤더를 제거한다
        byte[] cpyInput = new byte[length - 4];
        System.arraycopy(input, 4, cpyInput, 0, length - 4);
        input = cpyInput;
        return input;
    }

    private void fragSend(byte[] input, int length) {
        byte[] bytes = new byte[1456];
        int i = 0;
        m_sHeader.capp_totlen = intToByte2(length); // 데이터 전체 길이

        // 첫번째 전송
        m_sHeader.capp_type = (byte) (0x01); // 타입: 1번째 fragment
        System.arraycopy(input, 0, bytes, 0, 1456); // 1번째 fragment 추출
        bytes = objToByte(m_sHeader, bytes, 1456); // Header 부착
        this.GetUnderLayer().Send(bytes, bytes.length); // 전송

        int maxLen = length / 1456;
        	/*과제  */
        for(i = 0; i < maxLen-1; i++) {
        	if(length % 1456 == 0 && i == maxLen-2) {
        		m_sHeader.capp_type = (byte) (0x03); // ChatApp:type = 마지막 fragment
        	} else {
        		m_sHeader.capp_type = (byte) (0x02); // ChatApp:type = 중간 fragment
        	}
        	
        	int srcPos = (i+1)*1456; // 현재 fragment 첫번째 byte 위치
        	
        	System.arraycopy(input, srcPos, bytes, 0, 1456); // i+1번째 fragment 추출
            bytes = objToByte(m_sHeader, bytes, 1456); // Header 부착
            this.GetUnderLayer().Send(bytes, bytes.length); // 전송
        }

        if (length % 1456 != 0) {
            m_sHeader.capp_type = (byte) (0x03); // ChatApp:type = 마지막 fragment
            /*과제  */
            int lastLength = length-maxLen*1456;
            System.arraycopy(input, maxLen*1456, bytes, 0, lastLength); // 마지막 fragment 추출
            bytes = objToByte(m_sHeader, bytes, lastLength); // Header 부착
            this.GetUnderLayer().Send(bytes, bytes.length); // 전송
        }
    }
 
    public boolean Send(byte[] input, int length) {
        byte[] bytes;
        m_sHeader.capp_totlen = intToByte2(length); // 데이터 전체 길이
        m_sHeader.capp_type = (byte) (0x00); // ChatApp:type 초기화
 
        /*  과제  
         */
        if (length > 1456) { // 길이가 1456 byte 초과 -> 단편화를 통한 복수 전송
        	fragSend(input, length);
        } else { // 길이가 1456 byte 이하 -> 단편화 없는 단일 전송
        	bytes = objToByte(m_sHeader, input, length);
        	boolean result = this.GetUnderLayer().Send(bytes, length+4);
        	return result;
        }
        return true;
    }
 
    public synchronized boolean Receive(byte[] input) {
        byte[] data, tempBytes;
        int tempType = 0;

        if (input == null) { // ACK 수신 시
        	ackChk.add(true);
        	return true;
        }
        
        // Normal 수신 시
        tempType |= (byte) (input[2] & 0xFF); // ChatApp:type
        
        if(tempType == 0) {
            /*  과제   */
        	data = RemoveCappHeader(input, input.length);
        	this.GetUpperLayer(0).Receive(data);
        }
        else{
            /*  과제   */
        	if(tempType == 1 && fragCount == 0) { // ChatApp:type = 1(1번째 fragment)
        		int totalLength = byte2ToInt(input[0], input[1]);
        		fragBytes = new byte[totalLength];
        		tempBytes = RemoveCappHeader(input, input.length);
        		System.arraycopy(tempBytes, 0, fragBytes, 0, 1456);
        		fragCount++;
        	} else if (tempType == 2 || tempType == 3 && fragCount != 0) {
        		if(tempType == 2) { // ChatApp:type = 2(중간 fragment)
        			tempBytes = RemoveCappHeader(input, input.length); // 이어붙일 조각
        			System.arraycopy(tempBytes, 0, fragBytes, 1456*fragCount, 1456);
        			fragCount++;
        		} else if(tempType == 3) { // ChatApp:type = 3(마지막 fragment)
        			tempBytes = RemoveCappHeader(input, input.length); // 이어붙일 조각
        			System.arraycopy(tempBytes, 0, fragBytes, 1456*fragCount, tempBytes.length);
        			this.GetUpperLayer(0).Receive(fragBytes);
        			fragCount = 0;
        		} else {
        			return false;
        		}
        	} else {
        		return false;
        	}
        }
        
        return true;
    }
    
    private byte[] intToByte2(int value) {
        byte[] temp = new byte[2];
        temp[0] |= (byte) ((value & 0xFF00) >> 8);
        temp[1] |= (byte) (value & 0xFF);

        return temp;
    }

    private int byte2ToInt(byte value1, byte value2) {
        return (int)((value1 << 8) | (value2));
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
