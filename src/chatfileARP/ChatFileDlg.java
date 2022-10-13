package chatfileARP;

import java.awt.Color;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;

import org.jnetpcap.PcapIf;

public class ChatFileDlg extends JFrame implements BaseLayer {

	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	private static LayerManager m_LayerMgr = new LayerManager();

	private JTextField ChattingWrite; // 채팅 내용 입력 텍스트 박스

	Container contentPane;

	JTextArea ChattingArea; // 채팅 박스(채팅 내역 출력)
	JTextArea srcMacAddress; // 근원지 MAC주소 텍스트 박스
	JTextArea srcIpAddress; // 근원지 IP주소 텍스트 박스
	JTextArea dstIpAddress; // 목적지 IP주소 텍스트 박스
	JTextArea fileDirectory; // 파일 주소 텍스트 박스
	JTextArea fileSaveDirectory; // 파일 저장 위치 텍스트 박스
	
	JTable ARPCacheTable; // ARP 캐시 테이블
	JTable ProxyTable; // Proxy 테이블
	JTextArea ipAddress; // ARP요청 대상 IP주소
	JTextArea macAddress; // Gratuitous ARP요청 MAC주소 

	JLabel labelSourceMac; // 근원지 주소 라벨
	JLabel labelSourceIp; // 목적지 주소 라벨
	JLabel labelDestinationIp; // 목적지 주소 라벨
	JLabel fileDir; // 파일 저장 위치 라벨
	
	JLabel ipAddr;
	JLabel macAddr;

	JButton Source_setting_Button; // Source Setting Setting/Reset 버튼
	JButton Communication_setting_Button; // Communication Setting Setting/Reset 버튼
	JButton Chat_send_Button; // 메세지 Send 버튼
	JButton Choose_file_Button;	// 파일 Choose 버튼
	JButton File_send_Button;  // 파일 Send 버튼
	JButton Choose_directory_Button; // 파일 저장 위치 Choose 버튼 
	
	JButton Item_delete_Button; // ARP 캐시 테이블 삭제 버튼
	JButton Delete_all_Button; // ARP 캐시 테이블 전체 삭제 버튼
	JButton IP_send_Button; // ARP요청 보내기 버튼
	JButton Proxy_add_Button; // Proxy 테이블 추가 버튼
	JButton Proxy_delete_Button; // Proxy 테이블 삭제 버튼
	JButton MAC_send_Button; // Gratuitous ARP요청 보내기 버튼

	static JComboBox<String> NICComboBox; // 네트워크 하드웨어 선택 드롭다운 리스트

	int adapterNumber = 3;
	
	JProgressBar progressBar;  // 로딩 바
	File targetFile;  // 보내고자하는 파일
	File targetDirectory; // 받은 파일을 저장하고자하는 위치

	public static void main(String[] args) {
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Ethernet"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new TCPLayer("TCP"));
		m_LayerMgr.AddLayer(new ChatAppLayer("ChatApp"));
		m_LayerMgr.AddLayer(new FileAppLayer("FileApp"));
		m_LayerMgr.AddLayer(new ChatFileDlg("GUI"));
		
		m_LayerMgr.ConnectLayers(" NI ( *Ethernet ( *ARP ( +GUI ) *IP ( *TCP ( *ChatApp ( *GUI ) *FileApp ( *GUI ) ) ) ) )");
		System.out.println();
	}

	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			// Source Setting Setting/Reset 버튼
			if (e.getSource() == Source_setting_Button) {
				if (Source_setting_Button.getText() == "Setting") { // Setting버튼
					byte[] sourceMacAddress = new byte[6];
					byte[] sourceIpAddress = new byte[4]; 
					
					String srcMac = srcMacAddress.getText(); 
					String srcIp = srcIpAddress.getText();
					
					// 입력 유효성 검사
					String macPattern = "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})";
					String ipPattern = "((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])([.](?!$)|$)){4}";
					if (!srcMac.matches(macPattern) || !srcIp.matches(ipPattern)) {
						JOptionPane.showMessageDialog(null, "주소들의 입력여부, 형식을 확인하세요", "경고", JOptionPane.WARNING_MESSAGE);
						return;
					}
					
					// 주소 추출
					String[] srcMacArray = srcMac.split("-");
					for (int i = 0; i< 6; i++) {
						sourceMacAddress[i] = (byte) Integer.parseInt(srcMacArray[i], 16);
					}
					String[] srcIpArray = srcIp.split("\\.");
					for (int i = 0; i < 4; i++) {
						sourceIpAddress[i] = (byte) Integer.parseInt(srcIpArray[i], 10);
					}
					
					// 주소 설정
					// EthernetLayer 주소 설정
					((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetSrcAddress(sourceMacAddress);
					// IPLayer 주소 설정
					((IPLayer) m_LayerMgr.GetLayer("IP")).SetIPSrcAddress(sourceIpAddress);
					// ARPLayer 주소 설정
					((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetHardwareSenderAddress(sourceMacAddress);
					((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetProtocolSenderAddress(sourceIpAddress);
					
					((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(adapterNumber);
					
					srcIpAddress.setEnabled(false);
					srcMacAddress.setEnabled(false);
					
					Source_setting_Button.setText("Reset");
				} else { // Reset 버튼
					// 입력 초기화
					srcMacAddress.setText("");
					srcIpAddress.setText("");
					
					// 텍스트 필드 활성화
					srcIpAddress.setEnabled(true);
					srcMacAddress.setEnabled(true);
					
					Source_setting_Button.setText("Setting");
				}
				
			}
			// Communication Setting Setting/Reset 버튼
			if (e.getSource() == Communication_setting_Button) {
				if (Communication_setting_Button.getText() == "Setting") { // Setting버튼
					// 채팅 대화 초기화
					ChattingArea.setText("");
					
					byte[] sourceMacAddress = new byte[6];
					byte[] destinationMacAddress = new byte[6];
					byte[] sourceIpAddress = new byte[4]; 
					byte[] destinationIpAddress = new byte[4]; 
					
					String srcMac = srcMacAddress.getText(); 
					String srcIp = srcIpAddress.getText();
					String dstIp = dstIpAddress.getText();
					
					// 입력 유효성 검사
					String macPattern = "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})";
					String ipPattern = "((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])([.](?!$)|$)){4}";
					if (!srcMac.matches(macPattern) || !srcIp.matches(ipPattern) || !dstIp.matches(ipPattern)) {
						JOptionPane.showMessageDialog(null, "주소들의 입력여부, 형식을 확인하세요", "경고", JOptionPane.WARNING_MESSAGE);
						return;
					}
					
					// 주소 추출
					String[] srcMacArray = srcMac.split("-");
					for (int i = 0; i< 6; i++) {
						sourceMacAddress[i] = (byte) Integer.parseInt(srcMacArray[i], 16);
					}
					String[] srcIpArray = srcIp.split("\\.");
					for (int i = 0; i < 4; i++) {
						sourceIpAddress[i] = (byte) Integer.parseInt(srcIpArray[i], 10);
					}
					String[] dstIpArray = dstIp.split("\\.");
					for (int i = 0; i < 4; i++) {
						destinationIpAddress[i] = (byte) Integer.parseInt(dstIpArray[i], 10);
					}
					
					// 상대방 MAC주소 얻어내기
					destinationMacAddress = ((ARPLayer) m_LayerMgr.GetLayer("ARP")).getTargetHardwareAddress(destinationIpAddress);
					if (destinationMacAddress == null) {
						JOptionPane.showMessageDialog(null, "ARP요청을 통해 하드웨어 주소를 먼저 확보하세요.", "경고", JOptionPane.WARNING_MESSAGE);
						return;
					}
					
					// 주소 설정
					// EthernetLayer 주소 설정
					((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetSrcAddress(sourceMacAddress);
					((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetDstAddress(destinationMacAddress);
					// IPLayer 주소 설정
					((IPLayer) m_LayerMgr.GetLayer("IP")).SetIPSrcAddress(sourceIpAddress);
					((IPLayer) m_LayerMgr.GetLayer("IP")).SetIPDstAddress(destinationIpAddress);
					// ARPLayer 주소 설정
					((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetHardwareSenderAddress(sourceMacAddress);
					((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetProtocolSenderAddress(sourceIpAddress);
					
					((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(adapterNumber);
					
					srcIpAddress.setEnabled(false);
					dstIpAddress.setEnabled(false);
					srcMacAddress.setEnabled(false);
					Chat_send_Button.setEnabled(true);
					Choose_file_Button.setEnabled(true);
					Choose_directory_Button.setEnabled(false);
					
					Communication_setting_Button.setText("Reset");
					
					ChattingArea.append("[채팅 시작]\n");
					
				} else { // Reset 버튼
					srcMacAddress.setText("");
					srcIpAddress.setText("");
					dstIpAddress.setText("");
					
					ChattingArea.setText("");
					
					srcIpAddress.setEnabled(true);
					dstIpAddress.setEnabled(true);
					srcMacAddress.setEnabled(true);
					Chat_send_Button.setEnabled(false);
					Choose_file_Button.setEnabled(false);
					Choose_directory_Button.setEnabled(true);
					
					Communication_setting_Button.setText("Setting");
				}
				
			}
			
			// 메세지 Send 버튼
			if (e.getSource() == Chat_send_Button) {
				if (Communication_setting_Button.getText() == "Reset") { 
					String input = ChattingWrite.getText(); 
					
					byte[] bytes = input.getBytes(); 
					boolean result = ((ChatAppLayer)m_LayerMgr.GetLayer("ChatApp")).Send(bytes, bytes.length);
					
					if (result) {
						ChattingArea.append("[SEND] : " + input + "\n");
					} else {
						ChattingArea.append("[전송에 실패하였습니다]\n");
					}
					
					ChattingWrite.setText("");
				} else { 
					JOptionPane.showMessageDialog(null, "Address Configuration Error");
				}
			}
			
			// 파일 저장 위치 Choose 버튼
			if (e.getSource() == Choose_directory_Button) {
				JFileChooser fileChooser = new JFileChooser();
				fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				int chooseResult = fileChooser.showOpenDialog(ChatFileDlg.this);
				if (chooseResult == fileChooser.APPROVE_OPTION) {
					targetDirectory = fileChooser.getSelectedFile();
					String path = targetDirectory.getPath() + File.separator;
					((FileAppLayer) m_LayerMgr.GetLayer("FileApp")).setFileSaveDirectory(path);
					fileSaveDirectory.setText(path);
				}
			}
			
			// 파일 Choose 버튼
			if (e.getSource() == Choose_file_Button) {
				JFileChooser fileChooser = new JFileChooser();
				fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
				int chooseResult = fileChooser.showOpenDialog(ChatFileDlg.this);
				if (chooseResult == fileChooser.APPROVE_OPTION) {
					targetFile = fileChooser.getSelectedFile();
					fileDirectory.setText(targetFile.getPath());
					File_send_Button.setEnabled(true);
				}
			}
			
			// 파일 Send 버튼
			if (e.getSource() == File_send_Button) {
				Send_File_Thread thread = new Send_File_Thread((FileAppLayer)m_LayerMgr.GetLayer("FileApp"));
				Thread send = new Thread(thread);
				send.start();
			}
			
			// ARP 테이블 삭제 버튼
			if (e.getSource() == Item_delete_Button) {
				// 선택된 요소 삭제
				int rowIndex = ARPCacheTable.getSelectedRow();
				
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).deleteCacheEntry(rowIndex);
				updateCacheTableGUI(((ARPLayer) m_LayerMgr.GetLayer("ARP")).getArpTableGUIContent());
			}
			// ARP 테이블 전체 삭제 버튼
			if (e.getSource() == Delete_all_Button) {
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).deleteAllCacheEntry();
				updateCacheTableGUI(((ARPLayer) m_LayerMgr.GetLayer("ARP")).getArpTableGUIContent());
			}
			// ARP요청 보내기 버튼
			if (e.getSource() == IP_send_Button) {
				String targetIP = ipAddress.getText();
				
				// 입력 유효성 검사
				String ipPattern = "((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])([.](?!$)|$)){4}";
				if (!targetIP.matches(ipPattern)) {
					JOptionPane.showMessageDialog(null, "올바른 형식의 IP주소를 입력해주세요!", "경고", JOptionPane.WARNING_MESSAGE);
					return;
				}
				
				// 주소 추출
				byte[] targetIpAddress = new byte[4];
				String[] targetIPArray = targetIP.split("\\.");
				for (int i = 0; i < 4; i++) {
					targetIpAddress[i] = (byte) Integer.parseInt(targetIPArray[i], 10);
				}
				
				// ARP요청 보내기
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).SendARP(targetIpAddress, 4);
			}
			// Proxy 테이블 추가 버튼
			if (e.getSource() == Proxy_add_Button) {
				// Proxy 엔트리를 위한 정보(.기기명, IP주소, MAC주소)를 입력받으며 유효성 검사도 수행한다
				String macPattern = "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})";
				String ipPattern = "((\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])([.](?!$)|$)){4}";
				
				String deviceName = JOptionPane.showInputDialog("호스트명을 입력해주세요.");
				//System.out.println(deviceName);
				String ipAddress = JOptionPane.showInputDialog("IP주소을 입력해주세요.");
				//System.out.println(ipAddress);
				if(!ipAddress.matches(ipPattern)) {
					JOptionPane.showMessageDialog(null, "올바른 형식의 IP주소를 입력해주세요!", "경고", JOptionPane.WARNING_MESSAGE);
					return;
				}
				String macAddress = JOptionPane.showInputDialog("MAC주소를 입력해주세요.");
				//System.out.println(macAddress);
				if(!macAddress.matches(macPattern)) {
					JOptionPane.showMessageDialog(null, "올바른 형식의 MAC주소를 입력해주세요!", "경고", JOptionPane.WARNING_MESSAGE);
					return;
				}
				
				// Proxy를 추가
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).addProxyEntry(deviceName, ipAddress, macAddress);
				updateProxyTableGUI(((ARPLayer) m_LayerMgr.GetLayer("ARP")).getProxyTableGUIContent());
			}
			// Proxy 테이블 삭제 버튼
			if (e.getSource() == Proxy_delete_Button) {
				// 선택된 요소 삭제
				int rowIndex = ProxyTable.getSelectedRow();
				
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).deleteProxyEntry(rowIndex);
				updateProxyTableGUI(((ARPLayer) m_LayerMgr.GetLayer("ARP")).getProxyTableGUIContent());
			}
			// Gratuitous ARP요청 버튼
			if (e.getSource() == MAC_send_Button) {
				String targetMAC = macAddress.getText();
				
				// 입력 유효성 검사
				String macPattern = "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})";
				if (!targetMAC.matches(macPattern)) {
					JOptionPane.showMessageDialog(null, "올바른 형식의 MAC주소를 입력해주세요!", "경고", JOptionPane.WARNING_MESSAGE);
					return;
				}
				
				// 주소 추출
				byte[] targetMacAddress = new byte[6];
				String[] targetMacArray = targetMAC.split("-");
				for (int i = 0; i < 6; i++) {
					targetMacAddress[i] = (byte) Integer.parseInt(targetMacArray[i], 16);
				}
				
				// 주소 설정
				// EthernetLayer 주소 설정
				((EthernetLayer) m_LayerMgr.GetLayer("Ethernet")).SetEnetDstAddress(new byte[] {(byte) 0xff,(byte) 0xff,(byte) 0xff,(byte) 0xff,(byte) 0xff,(byte) 0xff,(byte) 0xff});
				// ARPLayer 주소 설정
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).SetHardwareSenderAddress(targetMacAddress);
				
				srcMacAddress.setText(targetMAC);
				
				// Gratuitous ARP요청 보내기
				((ARPLayer) m_LayerMgr.GetLayer("ARP")).Send(targetMacAddress, 6);
			}
		}
	}

	public ChatFileDlg(String pName) {
		pLayerName = pName;

		setTitle("Chat&File Transfer"); // GUI 제목
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(250, 250, 1300, 440); // JFrame 크기
		contentPane = new JPanel();
		((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		// ARP캐시테이블 패널
		JPanel cacheTablePanel = new JPanel();
		cacheTablePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ARP Cache",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		cacheTablePanel.setBounds(590, 5, 340, 360);
		contentPane.add(cacheTablePanel);
		cacheTablePanel.setLayout(null);
		// ARP캐시테이블 패널 - 캐시테이블 출력 패널
		DefaultTableModel arpCacheModel = new DefaultTableModel();
		arpCacheModel.addColumn("IP 주소");
		arpCacheModel.addColumn("MAC 주소");
		arpCacheModel.addColumn("상태");
		ARPCacheTable = new JTable(arpCacheModel);
		JScrollPane arpScrollpane = new JScrollPane(ARPCacheTable);
		arpScrollpane.setBounds(10, 25, 320, 210);
		cacheTablePanel.add(arpScrollpane);
		// ARP캐시테이블 패널 - 테이블 조작 패널
		JPanel cacheTableManipulatePanel = new JPanel();
		cacheTableManipulatePanel.setBounds(10, 245, 320, 30);
		cacheTablePanel.add(cacheTableManipulatePanel);
		cacheTableManipulatePanel.setLayout(null);
		// ARP캐시테이블 패널 - IP주소 입력 패널
		JPanel ipAddressOuterPanel = new JPanel();
		ipAddressOuterPanel.setBounds(10, 285, 320, 20);
		cacheTablePanel.add(ipAddressOuterPanel);
		ipAddressOuterPanel.setLayout(null);
		
		ipAddr = new JLabel("IP 주소");
		ipAddr.setBounds(0, 0, 40, 20);
		ipAddressOuterPanel.add(ipAddr);
		
		JPanel ipAddressInputPanel = new JPanel();
		ipAddressInputPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		ipAddressInputPanel.setBounds(40, 0, 190, 20);
		ipAddressOuterPanel.add(ipAddressInputPanel);
		ipAddressInputPanel.setLayout(null);
		
		ipAddress = new JTextArea();
		ipAddress.setBounds(2, 2, 200, 20);
		ipAddressInputPanel.add(ipAddress);

		arpCacheModel.addRow(new Object[] {"123.123.123.123", "22:22:22:22:22:22", "3"});
		
		
		
		// Proxy테이블 패널
		JPanel proxyTablePanel = new JPanel();
		proxyTablePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Proxy ARP Entry",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		proxyTablePanel.setBounds(940, 5, 340, 275);
		contentPane.add(proxyTablePanel);
		proxyTablePanel.setLayout(null);
		
		DefaultTableModel proxyModel = new DefaultTableModel();
		proxyModel.addColumn("호스트명");
		proxyModel.addColumn("IP 주소");
		proxyModel.addColumn("MAC 주소");
		ProxyTable = new JTable(proxyModel);
		JScrollPane proxyScrollpane = new JScrollPane(ProxyTable);
		proxyScrollpane.setBounds(10, 25, 320, 210);
		proxyTablePanel.add(proxyScrollpane);
		
		JPanel proxyTableManipulatePanel = new JPanel();
		proxyTableManipulatePanel.setBounds(10, 245, 320, 20);
		proxyTablePanel.add(proxyTableManipulatePanel);
		proxyTableManipulatePanel.setLayout(null);
		
		proxyModel.addRow(new Object[] {"Host A", "123.123.123.123", "22:22:22:22:22:22"});
		
		// Gratuitous 패널
		JPanel gratuitousPanel = new JPanel();
		gratuitousPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Gratuitous ARP",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		gratuitousPanel.setBounds(940, 285, 340, 80);
		contentPane.add(gratuitousPanel);
		gratuitousPanel.setLayout(null);
		
		JPanel hwAddressOuterPanel = new JPanel();
		hwAddressOuterPanel.setBounds(10, 30, 320, 20);
		gratuitousPanel.add(hwAddressOuterPanel);
		hwAddressOuterPanel.setLayout(null);
		
		macAddr = new JLabel("H/W 주소");
		macAddr.setBounds(0, 0, 50, 20);
		hwAddressOuterPanel.add(macAddr);
		
		JPanel hwAddressInputPanel = new JPanel();
		hwAddressInputPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		hwAddressInputPanel.setBounds(50, 0, 180, 20);
		hwAddressOuterPanel.add(hwAddressInputPanel);
		hwAddressInputPanel.setLayout(null);
		
		macAddress = new JTextArea();
		macAddress.setBounds(2, 2, 200, 20);
		hwAddressInputPanel.add(macAddress);
		
		
		// 채팅 패널
		JPanel chattingPanel = new JPanel();// chatting panel
		chattingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "chatting",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		chattingPanel.setBounds(10, 5, 360, 276);
		contentPane.add(chattingPanel);
		chattingPanel.setLayout(null);
		// 채팅 패널 - 채팅 출력 패널
		JPanel chattingEditorPanel = new JPanel();// chatting write panel
		chattingEditorPanel.setBounds(10, 15, 340, 210);
		chattingPanel.add(chattingEditorPanel);
		chattingEditorPanel.setLayout(null);
		// 채팅 패널 - 채팅 출력 패널 - 출력창
		ChattingArea = new JTextArea();
		ChattingArea.setEditable(false);
		ChattingArea.setBounds(0, 0, 340, 210);
		chattingEditorPanel.add(ChattingArea);// chatting edit
		// 채팅 패널 - 채팅 입력 패널
		JPanel chattingInputPanel = new JPanel();// chatting write panel
		chattingInputPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		chattingInputPanel.setBounds(10, 230, 250, 20);
		chattingPanel.add(chattingInputPanel);
		chattingInputPanel.setLayout(null);
		// 채팅 패널 - 채팅 입력 패널 - 입력창
		ChattingWrite = new JTextField();
		ChattingWrite.setBounds(2, 2, 250, 20);// 249
		chattingInputPanel.add(ChattingWrite);
		ChattingWrite.setColumns(10);// writing area
		
		// 설정 패널
		JPanel sourceSettingPanel = new JPanel();
		sourceSettingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Source Setting",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		sourceSettingPanel.setBounds(380, 5, 200, 200);
		contentPane.add(sourceSettingPanel);
		sourceSettingPanel.setLayout(null);
		// 설정 패널 - 근원지 MAC주소 패널
		JPanel sourceMacAddressPanel = new JPanel();
		sourceMacAddressPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		sourceMacAddressPanel.setBounds(10, 96, 170, 20);
		sourceSettingPanel.add(sourceMacAddressPanel);
		sourceMacAddressPanel.setLayout(null);
		// 설정 패널 - 근원지 MAC주소 패널 제목
		labelSourceMac = new JLabel("Source Mac Address");
		labelSourceMac.setBounds(10, 75, 170, 20);
		sourceSettingPanel.add(labelSourceMac);
		// 설정 패널 - 근원지 MAC주소 패널 - 입력창 
		srcMacAddress = new JTextArea();
		srcMacAddress.setBounds(2, 2, 170, 20);
		sourceMacAddressPanel.add(srcMacAddress);// src address
		// 설정 패널 - 근원지 IP주소 패널
		JPanel sourceIpAddressPanel = new JPanel();
		sourceIpAddressPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		sourceIpAddressPanel.setBounds(10, 141, 170, 20);
		sourceSettingPanel.add(sourceIpAddressPanel);
		sourceIpAddressPanel.setLayout(null);
		// 설정 패널 - 근원지 IP주소 패널 제목
		labelSourceIp = new JLabel("Source IP Address");
		labelSourceIp.setBounds(10, 120, 190, 20);
		sourceSettingPanel.add(labelSourceIp);
		// 설정 패널 - 근원지 IP주소 패널 - 입력창
		srcIpAddress = new JTextArea();
		srcIpAddress.setBounds(2, 2, 170, 20);
		sourceIpAddressPanel.add(srcIpAddress);// dst address
		
		
		// 설정 패널
		JPanel communicationSettingPanel = new JPanel();
		communicationSettingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Communication Setting",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		communicationSettingPanel.setBounds(380, 210, 200, 180);
		contentPane.add(communicationSettingPanel);
		communicationSettingPanel.setLayout(null);
		// 설정 패널 - 목적지 IP주소 패널
		JPanel destinationMacAddressPanel = new JPanel();
		destinationMacAddressPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		destinationMacAddressPanel.setBounds(10, 40, 170, 20);
		communicationSettingPanel.add(destinationMacAddressPanel);
		destinationMacAddressPanel.setLayout(null);
		// 설정 패널 - 목적지 IP주소 패널 제목
		labelDestinationIp = new JLabel("Destination IP Address");
		labelDestinationIp.setBounds(10, 20, 190, 20);
		communicationSettingPanel.add(labelDestinationIp);
		// 설정 패널 - 목적지 IP주소 패널 - 입력창
		dstIpAddress = new JTextArea();
		dstIpAddress.setBounds(2, 2, 170, 20);
		destinationMacAddressPanel.add(dstIpAddress);// dst address

		JLabel NICLabel = new JLabel("Select NIC");
		NICLabel.setBounds(10, 20, 170, 20);
		sourceSettingPanel.add(NICLabel);

		NICComboBox = new JComboBox();
		NICComboBox.setBounds(10, 49, 170, 20);
		sourceSettingPanel.add(NICComboBox);

		for (int i = 0; ((NILayer) m_LayerMgr.GetLayer("NI")).getAdapterList().size() > i; i++) {
			PcapIf pcapIf = ((NILayer) m_LayerMgr.GetLayer("NI")).GetAdapterObject(i);
			NICComboBox.addItem(pcapIf.getDescription());
		}

		NICComboBox.addActionListener(new ActionListener() { // Event Listener

			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				JComboBox jcombo = (JComboBox) e.getSource();
				adapterNumber = jcombo.getSelectedIndex();
				System.out.println("Index: " + adapterNumber);
				try {
					srcMacAddress.setText("");
					srcMacAddress.append(get_MacAddress(((NILayer) m_LayerMgr.GetLayer("NI"))
							.GetAdapterObject(adapterNumber).getHardwareAddress()));

				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});

		try {// Init MAC Address
			srcMacAddress.append(get_MacAddress(
					((NILayer) m_LayerMgr.GetLayer("NI")).GetAdapterObject(adapterNumber).getHardwareAddress()));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		// 설정 패널 - 파일 저장 경로 패널
		JPanel fileSaveDirectoryPanel = new JPanel();
		fileSaveDirectoryPanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		fileSaveDirectoryPanel.setBounds(10, 80, 170, 20);
		communicationSettingPanel.add(fileSaveDirectoryPanel);
		fileSaveDirectoryPanel.setLayout(null);
		// 설정 패널 - 파일 저장 경로 패널 제목
		fileDir = new JLabel("File Save Directory");
		fileDir.setBounds(10, 60, 190, 20);
		communicationSettingPanel.add(fileDir);
		// 설정 패널 - 파일 저장 경로 패널 - 입력창
		fileSaveDirectory = new JTextArea();
		fileSaveDirectory.setBounds(2, 2, 170, 20);
		fileSaveDirectory.setEnabled(false);
		fileSaveDirectoryPanel.add(fileSaveDirectory);
		
		// 기본 경로
		fileSaveDirectory.setText(((FileAppLayer) m_LayerMgr.GetLayer("FileApp")).getFileSaveDirectory());
		
		
		JPanel filePanel = new JPanel();

		filePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "File Transfer", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		filePanel.setBounds(10, 285, 360, 80);
		contentPane.add(filePanel);
		filePanel.setLayout(null);

		JPanel fileChoosePanel = new JPanel();
		fileChoosePanel.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		fileChoosePanel.setBounds(10, 20, 250, 20);
		filePanel.add(fileChoosePanel);
		fileChoosePanel.setLayout(null);

		fileDirectory = new JTextArea();
		fileDirectory.setEditable(false);
		fileDirectory.setBounds(2, 2, 250, 20);
		fileChoosePanel.add(fileDirectory);

		Choose_file_Button = new JButton("Choose");
		Choose_file_Button.setBounds(270, 20, 80, 20);
		Choose_file_Button.addActionListener(new setAddressListener());
		Choose_file_Button.setEnabled(false);
		filePanel.add(Choose_file_Button);

		progressBar = new JProgressBar(0, 100);
		progressBar.setBounds(10, 50, 250, 20);
		progressBar.setStringPainted(true);
		filePanel.add(this.progressBar);

		File_send_Button = new JButton("Send");
		File_send_Button.setBounds(270, 50, 80, 20);
		File_send_Button.addActionListener(new setAddressListener());
		File_send_Button.setEnabled(false);
		filePanel.add(File_send_Button);

		
		Choose_directory_Button = new JButton("Choose");
		Choose_directory_Button.setBounds(50, 110, 80, 20);
		Choose_directory_Button.addActionListener(new setAddressListener());
		communicationSettingPanel.add(Choose_directory_Button);// chatting send button
		
		
		Source_setting_Button = new JButton("Setting");// setting
		Source_setting_Button.setBounds(50, 170, 100, 20);
		Source_setting_Button.addActionListener(new setAddressListener());
		sourceSettingPanel.add(Source_setting_Button);// setting

		Communication_setting_Button = new JButton("Setting");// setting
		Communication_setting_Button.setBounds(50, 140, 100, 20);
		Communication_setting_Button.addActionListener(new setAddressListener());
		communicationSettingPanel.add(Communication_setting_Button);// setting

		Chat_send_Button = new JButton("Send");
		Chat_send_Button.setBounds(270, 230, 80, 20);
		Chat_send_Button.addActionListener(new setAddressListener());
		Chat_send_Button.setEnabled(false);
		chattingPanel.add(Chat_send_Button);// chatting send button
		
		
		
		Item_delete_Button = new JButton("Item Delete");
		Item_delete_Button.setBounds(40, 0, 100, 30);
		Item_delete_Button.addActionListener(new setAddressListener());
		cacheTableManipulatePanel.add(Item_delete_Button);
		
		Delete_all_Button = new JButton("Delete All");
		Delete_all_Button.setBounds(180, 0, 100, 30);
		Delete_all_Button.addActionListener(new setAddressListener());
		cacheTableManipulatePanel.add(Delete_all_Button);
		
		IP_send_Button = new JButton("Send");
		IP_send_Button.setBounds(240, 0, 80, 20);
		IP_send_Button.addActionListener(new setAddressListener());
		ipAddressOuterPanel.add(IP_send_Button);
		
		Proxy_add_Button = new JButton("Add");
		Proxy_add_Button.setBounds(40, 0, 100, 20);
		Proxy_add_Button.addActionListener(new setAddressListener());
		proxyTableManipulatePanel.add(Proxy_add_Button);
		
		Proxy_delete_Button = new JButton("Delete");
		Proxy_delete_Button.setBounds(180, 0, 100, 20);
		Proxy_delete_Button.addActionListener(new setAddressListener());
		proxyTableManipulatePanel.add(Proxy_delete_Button);
		
		MAC_send_Button = new JButton("Send");
		MAC_send_Button.setBounds(245, 0, 70, 20);
		MAC_send_Button.addActionListener(new setAddressListener());
		hwAddressOuterPanel.add(MAC_send_Button);
		
		

		setVisible(true);

	}

	public String get_MacAddress(byte[] byte_MacAddress) {

		String MacAddress = "";
		for (int i = 0; i < 6; i++) {
			MacAddress += String.format("%02X%s", byte_MacAddress[i], (i < MacAddress.length() - 1) ? "" : "");
			if (i != 5) {
				MacAddress += "-";
			}
		}

		System.out.println("present MAC address: " + MacAddress);
		return MacAddress;
	}
	
	
	
	///////////////////////////////////////////////////////////
	class Send_File_Thread implements Runnable{
		private FileAppLayer fileLayer;
		public Send_File_Thread(FileAppLayer fileLayer){
			this.fileLayer = fileLayer;
		}
		@Override
		public void run() {
			fileLayer.setAndStartSendFile();
		}
	}
	
	public File getFile() {
		return targetFile; // FileAppLayer에서 사용
	}
	///////////////////////////////////////////////////////////
	
	
	
	public boolean Receive(byte[] input) {
		if (input != null) {
			byte[] data = input;
			String receivedText = new String(data);
			ChattingArea.append("[RECV] : " + receivedText + "\n");
			return false;
		}
		return false;
	}
	
	
	public void updateCacheTableGUI(ArrayList<String[]> guiContent) {
		DefaultTableModel dm = (DefaultTableModel) this.ARPCacheTable.getModel();
		while(dm.getRowCount() > 0) {
			dm.removeRow(0);
		}
		for(Object[] anEntry: guiContent) {
			DefaultTableModel model = (DefaultTableModel) this.ARPCacheTable.getModel();
			model.addRow(anEntry);
		}
	}
	public void updateProxyTableGUI(ArrayList<String[]> guiContent) {
		DefaultTableModel dm = (DefaultTableModel) this.ARPCacheTable.getModel();
		while(dm.getRowCount() > 0) {
			dm.removeRow(0);
		}
		for(Object[] anEntry: guiContent) {
			DefaultTableModel model = (DefaultTableModel) this.ProxyTable.getModel();
			model.addRow(anEntry);
		}
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
		// nUpperLayerCount++;
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
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);

	}
}