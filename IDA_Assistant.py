import threading
import json
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_name
import ida_bytes
import idc
import idautils
import idaapi
import anthropic
import re
import traceback
import functools
import fuzzywuzzy
from PyQt5 import QtWidgets, QtCore
import os
import base64
import hashlib
import secrets

class ApiKeyManager:
    def __init__(self):
        # IDA 설치 디렉토리 내 config 폴더에 파일 저장
        self.config_dir = os.path.join(idaapi.get_user_idadir(), "plugins")
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        
        self.api_key_file = os.path.join(self.config_dir, "ida_assistant_api.enc")
        self.salt_file = os.path.join(self.config_dir, "ida_assistant_salt.bin")
    
    def _get_machine_specific_key(self):
        """기기 특정 고유 식별자를 기반으로 키 생성"""
        # IDA 설치 경로와 사용자 이름을 조합하여 고유한 값 생성
        machine_info = idaapi.get_user_idadir() + os.getenv('USERNAME', 'user')
        # SHA-256 해시 생성
        return hashlib.sha256(machine_info.encode()).digest()
    
    def _encrypt(self, data, salt):
        """간단한 XOR 기반 암호화"""
        key = self._get_machine_specific_key()
        # 키 확장 (PBKDF2와 유사한 간단한 방식)
        derived_key = b''
        for i in range(32):  # 256비트 키 생성
            derived_key += hashlib.sha256(key + salt + bytes([i])).digest()
        derived_key = derived_key[:len(data)]
        
        # XOR 암호화
        encrypted = bytearray(len(data))
        for i in range(len(data)):
            encrypted[i] = data[i] ^ derived_key[i % len(derived_key)]
            
        return bytes(encrypted)
    
    def _decrypt(self, encrypted_data, salt):
        """XOR 암호화는 대칭이므로 같은 함수 사용"""
        return self._encrypt(encrypted_data, salt)  # XOR 암호화는 적용을 두 번 하면 원래 값으로 돌아옴
    
    def save_api_key(self, api_key):
        """API 키 암호화 및 저장"""
        # 랜덤 salt 생성
        salt = secrets.token_bytes(16)
        
        # API 키 암호화
        encrypted_api_key = self._encrypt(api_key.encode(), salt)
        
        # 암호화된 키와 salt 저장
        with open(self.api_key_file, 'wb') as f:
            f.write(base64.b64encode(encrypted_api_key))
        
        with open(self.salt_file, 'wb') as f:
            f.write(base64.b64encode(salt))
        
        return True
    
    def load_api_key(self):
        """저장된 API 키 로드 및 복호화"""
        if not os.path.exists(self.api_key_file) or not os.path.exists(self.salt_file):
            return None
        
        try:
            # salt 로드
            with open(self.salt_file, 'rb') as f:
                salt = base64.b64decode(f.read())
            
            # 암호화된 API 키 로드 및 복호화
            with open(self.api_key_file, 'rb') as f:
                encrypted_api_key = base64.b64decode(f.read())
            
            decrypted_api_key = self._decrypt(encrypted_api_key, salt).decode()
            
            return decrypted_api_key
        except Exception as e:
            print(f"API 키 로드 중 오류 발생: {e}")
            return None
    
    def has_saved_api_key(self):
        """저장된 API 키가 있는지 확인"""
        return os.path.exists(self.api_key_file) and os.path.exists(self.salt_file)
    
    def delete_api_key(self):
        """저장된 API 키 파일을 삭제합니다"""
        try:
            if os.path.exists(self.api_key_file):
                os.remove(self.api_key_file)
            if os.path.exists(self.salt_file):
                os.remove(self.salt_file)
            return True
        except Exception as e:
            print(f"API 키 삭제 중 오류 발생: {e}")
            return False

class ApiKeyDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, current_key=None):
        super(ApiKeyDialog, self).__init__(parent)
        self.setWindowTitle("Anthropic API Key Setup")
        self.resize(450, 150)
        
        layout = QtWidgets.QVBoxLayout(self)
        
        # 설명 라벨
        info_label = QtWidgets.QLabel(
            "Enter your Anthropic API key. The key will be encrypted and stored securely."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # API 키 입력 필드
        key_layout = QtWidgets.QHBoxLayout()
        self.key_input = QtWidgets.QLineEdit()
        self.key_input.setEchoMode(QtWidgets.QLineEdit.Password)
        if current_key:
            self.key_input.setText(current_key)
        key_layout.addWidget(QtWidgets.QLabel("API Key:"))
        key_layout.addWidget(self.key_input)
        
        # 보기/숨기기 버튼
        self.toggle_view_btn = QtWidgets.QPushButton("Show")
        self.toggle_view_btn.setCheckable(True)
        self.toggle_view_btn.clicked.connect(self.toggle_key_visibility)
        key_layout.addWidget(self.toggle_view_btn)
        
        layout.addLayout(key_layout)
        
        # 버튼 레이아웃
        button_layout = QtWidgets.QHBoxLayout()
        self.save_button = QtWidgets.QPushButton("Save")
        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.clear_button = QtWidgets.QPushButton("Clear Key")
        
        self.save_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        self.clear_button.clicked.connect(self.clear_api_key)
        
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        # 키가 없으면 Clear 버튼 비활성화
        self.clear_button.setEnabled(current_key is not None)
        
        self.setLayout(layout)
    
    def toggle_key_visibility(self):
        if self.toggle_view_btn.isChecked():
            self.key_input.setEchoMode(QtWidgets.QLineEdit.Normal)
            self.toggle_view_btn.setText("Hide")
        else:
            self.key_input.setEchoMode(QtWidgets.QLineEdit.Password)
            self.toggle_view_btn.setText("Show")
    
    def get_api_key(self):
        return self.key_input.text().strip()
        
    def clear_api_key(self):
        # 특별한 결과 코드를 사용하여 Clear 요청을 반환
        self.done(QtWidgets.QDialog.Accepted + 1)

class IDAAssistant(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "IDA Assistant powered by Anthropic"
    help = "Provides an AI assistant for reverse engineering tasks"
    wanted_name = "IDA Assistant"
    wanted_hotkey = "Alt-F1"

    def __init__(self):
        super(IDAAssistant, self).__init__()
        self.model = "claude-3-7-sonnet-latest"
        self.api_key_manager = ApiKeyManager()
        self.api_key = self.api_key_manager.load_api_key()
        self.client = None
        self.chat_history = []
        self.message_history = []
        
        # API 키가 없으면 None으로 초기화, 실제 사용 시 확인 후 요청
        if self.api_key:
            self.initialize_client()
        
        system_prompt = """
        # IDA-Assistant Core Purpose
        You are IDA-Assistant, an AI designed to assist users with reverse engineering and binary analysis tasks in IDA Pro. Your primary goal is to provide valuable insights, guidance, and automation to enhance the user's reverse engineering workflow.

        # Behavioral Guidelines
        - Provide concise, informative responses that directly address the user's needs
        - Prioritize user assistance and practical, actionable information
        - Apply your knowledge of reverse engineering concepts and techniques
        - Utilize the information from the current IDA Pro view/position
        - Utilize multiple commands when needed to solve complex problems
        - Do not repeat the same commands if the necessary information has already been obtained
        - When using commands, all parameters must be explicitly provided
        - Never attempt to use the result of one command as an argument for another command

        # Command Usage Rules
        - Each command must be independently executable
        - Do not chain commands in a way that depends on previous command results
        - When specifying addresses, always use explicit address strings (not references to previous results)
        - Commands must be used exactly as defined below with no modifications

        # Available Commands
        - Name: get_disassembly
          - Description: Gets the disassembly from start address to end address.
          - Args: "start_address": String, "end_address": String
        
        - Name: decompile_address
          - Description: Decompile the function at the specified address. 
          - Args: "address": String
        
        - Name: decompile_function
          - Description: Decompile the function with the specified name.
          - Args: "name": String
        
        - Name: rename_address
          - Description: Rename the address at the specified address.
          - Args: "address": String, "new_name": String, "old_name": String
        
        - Name: rename_function_var
          - Description: Rename the variable in the function.
          - Args: "address": String, "new_name": String, "old_name": String
        
        - Name: get_function_start_end_address
          - Description: Get the start and end address of the function at the specified address.
          - Args: "address": String
        
        - Name: get_addresses_of_name
          - Description: Search for a name in the IDA name list and get all matching addresses.
          - Args: "name": String
        
        - Name: get_xrefs_to
          - Description: Get the cross-references to the specified address.
          - Args: "address": String
        
        - Name: get_xrefs_from
          - Description: Get the cross-references from the specified address.
          - Args: "address": String
        
        - Name: get_func_xrefs_to
          - Description: Get the details of all cross-references to the specified function.
          - Args: "address": String
        
        - Name: complete_analysis
          - Description: Explicitly end the conversation when analysis is successfully completed. Use this command to signal that you have finished your analysis with successful results.
          - Args: None (include as {"args": {}})
        
        - Name: abort_analysis
          - Description: End the conversation when analysis cannot be completed or further progress is impossible. Use this command when you've reached a dead end, encountered insurmountable obstacles, or determined that the requested task cannot be accomplished.
          - Args: None (include as {"args": {}})
        
        - Name: set_address_comment
          - Description: Set a comment at the specified address.
          - Args: "address": String, "comment": String
        
        - Name: set_function_comment
          - Description: Set a comment at the specified function.
          - Args: "address": String, "comment": String
        
        - Name: get_address_type
          - Description: Get the type of the address.
          - Args: "address": String

        # INCORRECT Command Usage Example (DO NOT USE)
        ```json
        "command": [
            {
                "name": "get_address_of_name",
                "args": {"name": "dispatch::handler"}
            },
            {
                "name": "decompile_address",
                "args": {"address": "<result of previous command>"} 
            }
        ]
        ```

        # Self-Improvement Guidelines
        - Reflect on how well your suggestions assist the user
        - Assess whether the user finds your insights helpful and relevant
        - Consider alternate approaches that might be more efficient
        - Strive to provide maximum value with each interaction

        # Response Format
        You MUST respond ONLY in the following JSON format:
        {
            "thoughts": {
                "text": "Your detailed analysis and reasoning",
                "reasoning": "Step-by-step logical process",
                "criticism": "Self-assessment of limitations in your approach", 
                "speak": "Clear, concise summary for the user"
            },
            "command": [
                {
                    "name": "command_name",
                    "args": {"arg_name": "value"}
                }
            ]
        }

        # Response Rules
        - Ensure your response can be parsed by Python json.loads()
        - Strictly adhere to the specified JSON format
        - Do not provide any content outside this JSON format
        - If unable to format correctly, respond with an empty JSON object {}
        """
        
        self.system_prompt = [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"}
            }
        ]
        
    def initialize_client(self):
        """API 키로 Anthropic 클라이언트 초기화"""
        if self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            return True
        return False
    
    def ensure_api_key(self):
        """API 키가 설정되어 있는지 확인하고, 없으면 입력 요청"""
        if self.api_key and self.client:
            return True
        
        # API 키 입력 대화상자 표시
        dialog = ApiKeyDialog(None, self.api_key)
        result = dialog.exec_()
        
        if result == QtWidgets.QDialog.Accepted:
            # API 키 저장
            self.api_key = dialog.get_api_key()
            if self.api_key:
                # API 키 저장 및 클라이언트 초기화
                self.api_key_manager.save_api_key(self.api_key)
                return self.initialize_client()
        elif result == QtWidgets.QDialog.Accepted + 1:
            # API 키 삭제 요청
            if self.api_key_manager.delete_api_key():
                self.api_key = None
                self.client = None
                return False
        
        return False

    def init(self):
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        # 실행 시 API 키 확인
        if not self.ensure_api_key():
            print("API key is required to use IDA Assistant.")
            return
            
        self.assistant_window = AssistantWidget()
        self.assistant_window.Show("IDA Assistant")

    def term(self):
        pass

    def add_assistant_message(self, message):
        # 일반 텍스트 형식으로 변경
        self.chat_history.append(f"Bob: {message}")
        
    def query_model(self, role, query, cb, additional_model_options=None):
        # API 키 확인
        if not self.ensure_api_key():
            self.chat_history.append("System Message: API key not provided. Please configure your API key to use IDA Assistant.")
            return
            
        if additional_model_options is None:
            additional_model_options = {}
            
        self.message_history.append({"role": role, "content": query})
        
        import time
        retry_delay = 10  # 재시도 대기 시간(초)

        # 간단한 토큰 수 계산 함수 (평균 4문자/토큰 가정)
        def count_tokens(text):
            return len(text) // 4

        while True:
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=additional_model_options.get("max_tokens", 8000),
                    system=self.system_prompt[0]["text"],
                    messages=self.message_history,
                    temperature=0.0
                )
                break  # 성공하면 반복문 탈출
            except anthropic.RateLimitError as e:
                print(f"Rate limit reached: {e}. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            except anthropic.BadRequestError as e:
                error_msg = str(e)
                if "prompt is too long" in error_msg:
                    print(f"Prompt too long, attempting to truncate message history. {error_msg}")
                    # 메시지 히스토리를 줄여 프롬프트 길이가 제한 이내가 될 때까지 오래된 메시지 제거
                    while True:
                        system_text = ""
                        for item in self.system_prompt:
                            if item.get("type") == "text":
                                system_text += item.get("text") + "\n"
                        messages_text = ""
                        for m in self.message_history:
                            if m["role"] == "assistant":
                                messages_text += f"\n\nAssistant: {m['content']}"
                            else:
                                messages_text += f"\n\nHuman: {m['content']}"
                        full_prompt = system_text + messages_text + "\n\nAssistant:"
                        if count_tokens(full_prompt) <= 200000:
                            break
                        if len(self.message_history) > 1:
                            removed = self.message_history.pop(0)
                            print(f"Removed message to reduce prompt length: {removed}")
                        else:
                            print("Cannot truncate further.")
                            break
                    continue  # 재시도
                else:
                    print("BadRequestError not related to prompt length.")
                    raise
            except Exception as e:
                print(f"Error calling Anthropic API: {e}")
                self.chat_history.append(f"System Message: Error: {str(e)}")
                return

        assistant_reply = ""
        for block in response.content:
            if block.type == "text":
                assistant_reply += block.text or ""
        assistant_reply = assistant_reply.strip()
        print(assistant_reply)
                
        self.message_history.append({"role": "assistant", "content": assistant_reply})
        # 일반 텍스트로 변경
        self.chat_history.append(f"User: {query}")
        ida_kernwin.execute_sync(functools.partial(cb, response=assistant_reply), ida_kernwin.MFF_WRITE)


    def query_model_async(self, role, query, cb, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}
        t = threading.Thread(target=self.query_model, args=[role, query, cb, additional_model_options])
        t.start()
        

    def query_model_sync(self, role, query, cb, additional_model_options=None):
        if additional_model_options is None:
            additional_model_options = {}
        self.query_model(role, query, cb, additional_model_options)

class InputEventFilter(QtCore.QObject):
    def __init__(self, parent=None, callback=None):
        super(InputEventFilter, self).__init__(parent)
        self.callback = callback
        
    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.KeyPress:
            # Shift+Enter 처리: 줄바꿈 추가
            if event.key() == QtCore.Qt.Key_Return and event.modifiers() & QtCore.Qt.ShiftModifier:
                return False  # 기본 동작 허용 (줄바꿈)
            # Enter만 누를 경우 메시지 전송
            elif event.key() == QtCore.Qt.Key_Return:
                if self.callback:
                    self.callback()
                return True  # 이벤트 소비
        return False  # 기본 이벤트 처리

class AssistantWidget(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        
        # 대화 제어 변수 초기화 (PopulateForm 호출 전에 수행하여 update_button_states에 사용 가능하도록 함)
        self.stop_flag = False            # 중지 예약 플래그
        self.conversation_active = False  # 대화 상태 (활성/비활성)
        self.pending_message = None       # 전송 대기 중인 메시지 (단일 메시지 큐)
        self.processing_lock = False      # 처리 중복 방지 잠금
        
        self.PopulateForm()
        
        self.assistant = IDAAssistant()
        
        # API 키 확인
        if not self.assistant.ensure_api_key():
            self.chat_history.appendPlainText("System Message: API key not configured. Please configure your API key to use IDA Assistant.")
        
        self.command_results = []
        self.functions = self.get_name_info()
        
    def PopulateForm(self):
        layout = QtWidgets.QVBoxLayout()
        
        self.view = ida_kernwin.get_current_viewer()
        self.output_window = ida_kernwin.find_widget("Output window")
        
        # QTextEdit 대신 QPlainTextEdit 사용
        self.chat_history = QtWidgets.QPlainTextEdit()
        self.chat_history.setReadOnly(True)
        layout.addWidget(self.chat_history)
        
        input_layout = QtWidgets.QHBoxLayout()
        
        # QLineEdit 대신 QTextEdit 사용하여 다중 라인 입력 지원
        self.user_input = QtWidgets.QTextEdit()
        self.user_input.setMinimumHeight(70)
        self.user_input.setMaximumHeight(150)
        
        # Shift+Enter 키 처리를 위한 설정 - 별도의 QObject 기반 이벤트 필터 사용
        self.input_event_filter = InputEventFilter(parent=self.user_input, callback=self.OnSendClicked)
        self.user_input.installEventFilter(self.input_event_filter)
        
        input_layout.addWidget(self.user_input)
        
        button_layout = QtWidgets.QVBoxLayout()
        
        # 전송 버튼 (Send/Cancel)
        self.send_button = QtWidgets.QPushButton("Send")
        self.send_button.clicked.connect(self.OnSendClicked)
        button_layout.addWidget(self.send_button)
        
        # 중단 버튼 (Stop/Continue)
        self.stop_button = QtWidgets.QPushButton("Stop")
        self.stop_button.clicked.connect(self.OnStopClicked)
        self.stop_button.setEnabled(False)  # 초기에는 비활성화
        button_layout.addWidget(self.stop_button)
        
        # API 키 설정 버튼 추가
        api_key_button = QtWidgets.QPushButton("Set API Key")
        api_key_button.clicked.connect(self.OnSetApiKeyClicked)
        button_layout.addWidget(api_key_button)
        
        input_layout.addLayout(button_layout)
        
        layout.addLayout(input_layout)
        
        # 키 사용 안내 라벨 추가
        help_label = QtWidgets.QLabel("Shift+Enter: 줄바꿈 / Enter: 메시지 전송")
        help_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(help_label)
        
        self.parent.setLayout(layout)
        
        # 초기 버튼 상태 설정
        self.update_button_states()
    
    def OnSetApiKeyClicked(self):
        """API 키 설정 버튼 클릭 시 호출되는 함수"""
        # 이미 API 키가 있는 경우 메시지 박스 표시
        if self.assistant.api_key:
            msg_box = QtWidgets.QMessageBox()
            msg_box.setWindowTitle("API Key 설정")
            msg_box.setText("API 키가 이미 설정되어 있습니다. 변경하시겠습니까?")
            msg_box.setIcon(QtWidgets.QMessageBox.Information)
            msg_box.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            result = msg_box.exec_()
            
            if result == QtWidgets.QMessageBox.No:
                return
        
        # API 키 입력 대화상자 표시
        dialog = ApiKeyDialog(None, self.assistant.api_key)
        result = dialog.exec_()
        
        if result == QtWidgets.QDialog.Accepted:
            # API 키 저장
            new_api_key = dialog.get_api_key()
            if new_api_key:
                self.assistant.api_key = new_api_key
                self.assistant.api_key_manager.save_api_key(new_api_key)
                self.assistant.initialize_client()
                
                # 메시지 박스로 성공 메시지 표시
                QtWidgets.QMessageBox.information(
                    None, 
                    "API Key 설정", 
                    "API 키가 성공적으로 설정되었습니다.",
                    QtWidgets.QMessageBox.Ok
                )
            else:
                QtWidgets.QMessageBox.warning(
                    None, 
                    "API Key 설정", 
                    "API 키가 비어있습니다. 유효한 API 키를 입력해주세요.",
                    QtWidgets.QMessageBox.Ok
                )
        
        elif result == QtWidgets.QDialog.Accepted + 1:
            # API 키 삭제 요청
            if self.assistant.api_key_manager.delete_api_key():
                self.assistant.api_key = None
                self.assistant.client = None
                
                # 메시지 박스로 삭제 성공 메시지 표시
                QtWidgets.QMessageBox.information(
                    None, 
                    "API Key 삭제", 
                    "API 키가 성공적으로 삭제되었습니다.",
                    QtWidgets.QMessageBox.Ok
                )
                
                # 채팅 히스토리에 메시지 추가
                self.chat_history.appendPlainText("System Message: API key has been deleted. Please configure a new API key to use IDA Assistant.")
            else:
                # 메시지 박스로 삭제 실패 메시지 표시
                QtWidgets.QMessageBox.warning(
                    None, 
                    "API Key 삭제", 
                    "API 키 삭제 중 오류가 발생했습니다.",
                    QtWidgets.QMessageBox.Ok
                )

    def OnStopClicked(self):
        # 대화가 활성화된 상태에서만 작동
        if not self.conversation_active:
            return
            
        # 이미 중지 요청한 경우
        if self.stop_flag:
            self.PrintOutput("Stop request already in progress...")
            return
            
        # 중지 플래그 설정 및 상태 업데이트
        self.stop_flag = True
        self.update_button_states()
        
        self.PrintOutput("Stopping conversation after current response...")

    def OnSendClicked(self):
        # 대기 메시지가 있을 경우 (Cancel 동작)
        if self.pending_message is not None:
            if self.clear_queue():
                self.PrintOutput("Pending message canceled.")
            return
            
        # 메시지 입력 확인
        user_message = self.user_input.toPlainText().strip()
        if not user_message:
            return
            
        # 메시지를 대기열에 추가
        self.add_to_queue(user_message)
        
        # 대화가 활성화되지 않은 경우 처리 시작
        if not self.conversation_active:
            self.start_conversation_loop()
    
    def OnResponseReceived(self, response):
        try:
            assistant_reply = self.ParseResponse(response)

            if assistant_reply is None:
                self.end_conversation_loop("Failed to parse response.")
                return

            if not assistant_reply:
                self.end_conversation_loop("No response received.")
                return

            # 일반 텍스트로 변경
            self.chat_history.appendPlainText(f"Bob speak: {assistant_reply['thoughts']['speak']}")

            commands = assistant_reply['command']
            command_results = {}
            
            # AI가 대화를 중단하는지 확인
            ai_stops_conversation = False
            analysis_completed_successfully = False
            
            # 대화 종료 명령 확인 - 성공 또는 실패로 인한 종료
            for command in commands:
                if command['name'] == "complete_analysis":
                    ai_stops_conversation = True
                    analysis_completed_successfully = True
                    break
                elif command['name'] == "abort_analysis":
                    ai_stops_conversation = True
                    analysis_completed_successfully = False
                    break
            
            # AI가 대화를 중단하는 경우 처리
            if ai_stops_conversation:
                if analysis_completed_successfully:
                    self.end_conversation_loop("Analysis completed successfully by AI.")
                else:
                    self.end_conversation_loop("Analysis aborted: AI could not complete the requested task.")
                return

            # 명령어 처리
            for command in commands:
                command_name = command['name']
                if command_name in ["complete_analysis", "abort_analysis"]:
                    continue

                command_args = command['args']

                command_handler = getattr(self, f"handle_{command_name}", None)
                if command_handler:
                    command_results[command_name] = command_handler(command_args)
                else:
                    self.PrintOutput(f"Unknown command: {command_name}")
                    command_results[command_name] = None

            # Added check after processing commands to handle stop request after full response handling
            if self.stop_flag:
                self.end_conversation_loop("Conversation stopped by user after processing response.")
                return

            # 결과 처리 및 다음 메시지 요청
            query = ""
            for command_name, result in command_results.items():
                if result is not None:
                    query += f"{command_name} result:\n{json.dumps(result)}\n\n"
                else:
                    query += f"{command_name} result: None\n\n"
                    
            if len(query) > 0:
                # 중지 요청이 있는 경우 다음 메시지 처리하지 않음
                if self.stop_flag:
                    self.end_conversation_loop("Conversation stopped by user during command processing.")
                    return
                    
                self.assistant.query_model_async("user", f"{query}", self.OnResponseReceived, additional_model_options={"max_tokens": 8000})
            else:
                # 명령어가 없거나 더 이상 처리할 작업이 없는 경우
                self.processing_lock = False
                
                # 다음 메시지 처리, 큐가 비어있으면 대화 종료
                if self.pending_message is not None:
                    self.process_next_message()
                else:
                    self.end_conversation_loop()

        except Exception as e:
            traceback_details = traceback.format_exc()
            print(traceback_details)
            self.PrintOutput(f"Error parsing response: {str(e)}")
            self.end_conversation_loop(f"Error occurred: {str(e)}")

    def handle_eval_idc(self, args):
        try:
            idc_expression = args["idc_expression"]
            result = idc.eval_idc(idc_expression)
            return result
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_get_disassembly(self, args):
        try:
            start_address = int(args["start_address"], 16)
            end_address = int(args["end_address"], 16)

            disassembly = ""
            while start_address < end_address:
                disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                start_address = idc.next_head(start_address)
            return disassembly
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_get_disassembly_function(self, args):
        try:
            name = args["name"]
            address = idc.get_name_ea_simple(name)
            if address != idc.BADADDR:
                func = idaapi.get_func(address)
                if func:
                    start_address = func.start_ea
                    end_address = func.end_ea

                    disassembly = ""
                    while start_address < end_address:
                        disassembly += f"{hex(start_address)}: {idc.GetDisasm(start_address)}\n"
                        start_address = idc.next_head(start_address)
                    return disassembly
            return f"No function found at address {name}"
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_decompile_address(self, args):
        try:
            address = int(args["address"], 16)
            function = idaapi.get_func(address)
            if function:
                decompiled_code = idaapi.decompile(function)
                if decompiled_code:
                    return str(decompiled_code)
            return f"No function found at address {hex(address)}"
        except Exception as e:
            return f"Error: {str(e)}"
        
    def handle_decompile_function(self, args):
        try:
            name = args["name"]
            name = name.strip()
            functions = {idaapi.get_func_name(ea).strip(): ea for ea in idautils.Functions()}
            best_match = fuzzywuzzy.process.extractOne(name, functions.keys(), score_cutoff=50)
            if best_match:
                if best_match[0] == name:
                    ea = functions[best_match[0]]
                    func = idaapi.get_func(ea)
                    if not func:
                        self.PrintOutput(f"No function found at address {name}")
                        return f"No function found at address {name}"
                    
                    cfunc = idaapi.decompile(func, flags=ida_hexrays.DECOMP_NO_CACHE)
                    return str(cfunc)
                else:
                    self.PrintOutput(f"Function '{name}' not found. Did you mean '{best_match[0]}'?")
                    return f"Function '{name}' not found. Did you mean '{best_match[0]}'?"

            return None
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_rename_address(self, args):
        try:
            address = int(args["address"], 16)
            new_name = args["new_name"]
            old_name = args["old_name"]
            if new_name and old_name:
                idaapi.set_name(address, new_name, ida_name.SN_NOWARN)
                result = f"Renamed address {hex(address)} from '{old_name}' to '{new_name}'"
                # 일반 텍스트로 변경
                self.chat_history.appendPlainText(f"System Message: {result}")
                self.PrintOutput(result)
                return None
            return None
        except Exception as e:
            return f"Error: {str(e)}"

    def handle_get_function_start_end_address(self, args):
        try:
            address = int(args["address"], 16)
            function = idaapi.get_func(address)
            if function:
                start_address = hex(function.start_ea)
                end_address = hex(function.end_ea)
                result = {"start_address": start_address, "end_address": end_address}
                return result
            else:
                self.PrintOutput(f"No function found at address {hex(address)}")
            return f"No function found at address {hex(address)}"
        except Exception as e:
            return f"Error: {str(e)}"
        
    def get_name_info(self):
        name_info = []

        for i in range(ida_name.get_nlist_size()):
            ea = ida_name.get_nlist_ea(i)
            name = ida_name.get_short_name(ea)
            name_info.append((name, hex(ea)))

        return name_info

    def search_name(self, keyword):        
        search_results = []
        
        temp = keyword.lower()
        temp = temp.strip()
        functions = {idaapi.get_func_name(ea).strip(): ea for ea in idautils.Functions()}
        best_match = fuzzywuzzy.process.extractOne(temp, functions.keys(), score_cutoff=50)
        if best_match:
            if best_match[0] == temp:
                ea = functions[best_match[0]]
                search_results.append((best_match[0], hex(ea)))
            else:
                search_results.append((f"Did you mean '{best_match[0]}'?", "0x0000"))
        
        return search_results
    
    def handle_get_addresses_of_name(self, args):
        try:
            name = args["name"]
            r = self.search_name(name)

            self.PrintOutput(f"Search results for '{name}': {r}")
            return r
        except Exception as e:
            return f"Error: {str(e)}"
        
    def get_type_ea(self, ea):
        flag_types = []
        flags = ida_bytes.get_flags(ea)
        if idc.is_code(flags):
            flag_types.append("CODE")
        if idc.is_data(flags):
            flag_types.append("DATA")
        if idc.is_unknown(flags):
            flag_types.append("UNKNOWN")
        return f"Flags: {' | '.join(flag_types)}"

    def handle_get_address_type(self, args):
        try:
            address = int(args["address"], 16)
            flag_types = self.get_type_ea(address)
            size = idc.get_item_size(address)
            type_info = idc.get_type(address)
            if type_info:
                size_type = type_info
            else:
                size_type = {
                    1: "byte",
                    2: "word",
                    4: "dword",
                    8: "qword",
                    16: "oword"
                }.get(size, f"Unknown size ({size} bytes)")
            
            return f"Flags: {' | '.join(flag_types)}, Size: {size} bytes ({size_type})"
        except Exception as e:
            return f"Error: {str(e)}"
        
    def handle_get_xrefs_to(self, args):
        try:
            address = int(args["address"], 16)
            xrefs = []
            for xref in idautils.XrefsTo(address, 0):
                xrefs.append((hex(xref.frm), self.get_type_ea(xref.frm), idautils.XrefTypeName(xref.type)))
            result = xrefs
            self.PrintOutput(f'Xrefs to {hex(address)}: {result}')
            return result
        except Exception as e:
            self.PrintOutput(f"handle_get_xrefs_to Error: {str(e)}")
            return f"Error: {str(e)}"

    def handle_get_xrefs_from(self, args):
        try:
            address = int(args["address"], 16)
            xrefs = []
            for xref in idautils.XrefsFrom(address, 0):
                xrefs.append((hex(xref.to), self.get_type_ea(xref.to), idautils.XrefTypeName(xref.type)))
            result = xrefs
            self.PrintOutput(f'Xrefs from {hex(address)}: {result}')
            return result
        except Exception as e:
            self.PrintOutput(f"handle_get_xrefs_from Error: {str(e)}")
            return f"Error: {str(e)}"

    def handle_get_func_xrefs_to(self, args):
        try:
            address = int(args["address"], 16)
            if address != idc.BADADDR:
                xrefs = []
                for xref in idautils.XrefsTo(address, 0):
                    xrefs.append((hex(xref.frm), self.get_type_ea(xref.frm), idautils.XrefTypeName(xref.type)))
                result = xrefs
                self.PrintOutput(f'Xrefs to function at {hex(address)}: {result}')                
                return result
            self.PrintOutput(f"No function found at address {hex(address)}")
            return f"No function found at address {hex(address)}"
        except Exception as e:
            self.PrintOutput(f"handle_get_func_xrefs_to Error: {str(e)}")
            return f"Error: {str(e)}"
        
    def handle_print(self, args):
        message = args["message"]
        self.PrintOutput(message)
        return None

    def handle_set_address_comment(self, args):
        try:
            address = int(args["address"], 16)
            new_comment = args["comment"]
            
            # 기존 코멘트 가져오기 (repeatable comment = 1)
            existing_comment = idc.get_cmt(address, 1)
            
            # 기존 코멘트가 있으면 새 코멘트와 합치기
            if existing_comment:
                combined_comment = f"{existing_comment}\n{new_comment}"
            else:
                combined_comment = new_comment
                
            # 합쳐진 코멘트 설정
            idc.set_cmt(address, combined_comment, 1)
            
            result = f"Set comment at {hex(address)}: {combined_comment}"
            # 일반 텍스트로 변경
            self.chat_history.appendPlainText(f"System Message: {result}")
            self.PrintOutput(result)

            return None
        except Exception as e:
            return f"Error: {str(e)}"
    
    def handle_set_function_comment(self, args):
        try:
            address = int(args["address"], 16)
            comment = args["comment"]
            function = idaapi.get_func(address)
            if function:
                existing_comment = idc.get_func_cmt(address, 0)
                existing_comment = re.sub(
                    r'----- Comment generated by Bob -----.*?----------------------------------------',
                    r"",
                    existing_comment if existing_comment else "",
                    flags=re.DOTALL)
                
                idc.set_func_cmt(address, '----- Comment generated by Bob' +
                                    f" -----\n\n"
                                    f"{existing_comment.strip()}\n\n"
                                    f"----------------------------------------\n\n"
                                    f"{comment.strip()}", 0)
                result = f"Set comment at function {hex(address)}."
                # 일반 텍스트로 변경
                self.chat_history.appendPlainText(f"System Message: {result}")
                self.PrintOutput(result)
                return None
            return f"No function found at address {hex(address)}"
        except Exception as e:
            return f"Error: {str(e)}"
        
    def handle_rename_function_var(self, args):
        try:
            address = int(args["address"], 16)
            new_name = args["new_name"]
            old_name = args["old_name"]
            function = idaapi.get_func(address).start_ea
            if function:
                if ida_hexrays.rename_lvar(function, old_name, new_name):
                    result = f"Renamed variable in function at {hex(address)} from '{old_name}' to '{new_name}'"
                    # 일반 텍스트로 변경
                    self.chat_history.appendPlainText(f"System Message: {result}")
                    self.PrintOutput(result)
                    return result
                else:
                    return f"Failed to rename variable in function at {hex(address)}"
            return f"No function found at address {hex(address)}"
        except Exception as e:
            return f"Error: {str(e)}"
        
    def sanitize_json(self, json_string):
        json_string = re.sub(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', '', json_string)
        json_string = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_string)
        json_string = re.sub(r'"\s*\n\s*"', '""', json_string)
        json_string = re.sub(r'\s*\n\s*', '', json_string)
        
        return json_string
    
    def ParseResponse(self, response):
        try:
            response = self.sanitize_json(response)
            parsed_response = json.loads(response)
            return parsed_response
        except json.JSONDecodeError as e:
            traceback_details = traceback.format_exc()
            print(traceback_details)
            raise e
        except Exception as e:
            print(str(e))
            traceback_details = traceback.format_exc()
            print(traceback_details)
            raise e
                
    def PrintOutput(self, output_str):
        print(output_str)
        # self.chat_history.append(f"<b>System Message:</b> {output_str}")
        
    def update_button_states(self):
        """대화 상태에 따라 버튼 상태와 텍스트를 업데이트합니다"""
        # 전송 버튼 상태 업데이트
        if self.pending_message is not None:
            self.send_button.setText("Cancel")
            # 전송 대기 중일 때 입력 박스 비활성화
            self.user_input.setEnabled(False)
        else:
            self.send_button.setText("Send")
            # 전송 대기 중이 아닐 때 입력 박스 활성화
            self.user_input.setEnabled(True)
            
        # 중단 버튼 상태 업데이트
        if self.conversation_active:
            self.stop_button.setEnabled(True)
            if self.stop_flag:
                self.stop_button.setText("Stopping...")
            else:
                self.stop_button.setText("Stop")
        else:
            self.stop_button.setEnabled(False)
            self.stop_button.setText("Stop")
    
    def add_to_queue(self, message):
        """메시지를 대기열에 추가하고 버튼 상태를 업데이트합니다"""
        self.pending_message = message
        self.update_button_states()
        
    def clear_queue(self):
        """대기 메시지를 취소하고 버튼 상태를 업데이트합니다"""
        if self.pending_message is not None:
            self.pending_message = None
            self.update_button_states()
            return True
        return False
    
    def process_next_message(self):
        """
        대기 중인 메시지를 처리합니다.
        """
        if self.pending_message is None or self.processing_lock:
            return
            
        # 처리 락 설정
        self.processing_lock = True
            
        # 대기 메시지 가져오기
        message = self.pending_message
        self.pending_message = None
        
        # 대화 상태 업데이트
        self.conversation_active = True
        self.update_button_states()
        
        # 메시지 처리
        self.stop_flag = False
        # 일반 텍스트로 변경
        self.chat_history.appendPlainText(f"User: {message}")
        
        # 이 시점에서 입력 필드를 초기화 (이전 메시지가 처리되기 시작할 때)
        self.user_input.clear()
        
        # 메시지 전송
        self.assistant.query_model_async("user", message, self.OnResponseReceived, additional_model_options={"max_tokens": 8000})

    def start_conversation_loop(self):
        """
        대화 루프를 시작합니다. 이미 활성화된 경우 아무것도 하지 않습니다.
        """
        if self.conversation_active:
            return
            
        self.conversation_active = True
        self.update_button_states()
        
        # 대기 메시지가 있는 경우 처리 시작
        if self.pending_message is not None and not self.processing_lock:
            self.process_next_message()

    def end_conversation_loop(self, message=None):
        """대화 루프를 종료합니다"""
        self.conversation_active = False
        self.processing_lock = False
        self.stop_flag = False
        
        if message:
            # 일반 텍스트로 변경
            self.chat_history.appendPlainText(f"System Message: {message}")
            
        self.update_button_states()

def PLUGIN_ENTRY():
    return IDAAssistant()
