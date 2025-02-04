"""
Author: CYTRIX
"""

import json

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from java.awt import FlowLayout, GridLayout
from java.awt.event import ActionListener
from javax.swing import (
    JPanel, JCheckBox, JLabel, JTextField, JButton, JTable, JScrollPane, BoxLayout,
    JOptionPane, JMenuItem
)
from javax.swing.border import EmptyBorder
from javax.swing.table import DefaultTableModel

from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import base64
import time
import re
import threading

BASE_URL_API      = "https://api.cytrix.io/Interception_"
API_FORWARD_URL   = BASE_URL_API + "UploadFile"
API_ALIVE_URL     = BASE_URL_API + "GetScanStatus"
API_PAUSE_URL     = BASE_URL_API + "TargetPause"
API_UNPAUSE_URL   = BASE_URL_API + "TargetUnPause"
CHECK_CREDENTIALS = BASE_URL_API + "CheckCreds"
CYTRIX            = "Cytrix"
API_KEY           = ""
SCAN_TOKEN        = ""
WILDCARD_REGEX    = "*"
LOGIN_FAILED      = "login failed"
LOGIN_SUCCESSFUL  = "login successful"
TARGET_CHANGED    = "Target Changed"


class BurpExtender(IBurpExtender, ITab, IHttpListener, ActionListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        callbacks.setExtensionName("Cytrix")

        self._mainPanel = self._build_ui()
        callbacks.addSuiteTab(self)

        # Initialize our new variable
        self.just_forwarded = False
        self._InterceptIsStatus = True
        # Register
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self._checkScanStatus()
        print("DEBUG: Extension loaded. Logs 'Yes', 'No', or 'Credentials not set' in the table, plus 'Clean' button.")

    def getTabCaption(self):
        return CYTRIX

    def getUiComponent(self):
        return self._mainPanel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """For each request, decide if we forward or not, then log 'Yes', 'No', or 'Credentials...'."""
        if not messageIsRequest:
            return

        api_key = API_KEY
        token   = getattr(self, "_token", "")

        try:
            analyzed = self._helpers.analyzeRequest(messageInfo)
            urlObj   = analyzed.getUrl()
            if not urlObj:
                self._logRequestInTable(messageInfo, False)  # No URL => 'No'
                return

            host = urlObj.getHost()
            path = urlObj.getPath()

            # Check credentials
            if not api_key or not token:
                self._logRequestInTable(messageInfo, "Credentials are not set")
                return

            # Check target
            if self._targetRegex is None:
                # * => forward all
                forward_now = True
            else:
                if host.startswith("www."):
                    host = host.replace("www.", "", 1)
                forward_now = bool(re.match(self._targetRegex, host+path))
            print("DEBUG: logreq3" , forward_now, host)
            if forward_now:
                # We forward => 'Yes'
                print("DEBUG: check1")
                request_str = self._helpers.bytesToString(messageInfo.getRequest())
                response_str = self._helpers.bytesToString(messageInfo.getResponse())
                print("DEBUG: check2")
                self._forward_request(api_key, token, request_str, response_str,
                                      messageInfo.getUrl(),messageInfo.getPort(), messageInfo.getProtocol())
                print("DEBUG: logreq2")
                self._logRequestInTable(messageInfo, True)
            else:
                # Mismatch => 'No'
                self._logRequestInTable(messageInfo, False)

        except Exception as e:
            print("DEBUG: processHttpMessage exception =>", e)
            self._logRequestInTable(messageInfo, False)

    def createMenuItems(self, invocation):
        menu = []
        sendItem = JMenuItem(
            "Send request to Cytrix",
            actionPerformed=lambda x: self._handleSendToCytrix(invocation)
        )
        menu.append(sendItem)
        return menu

    def _handleSendToCytrix(self, invocation):
        """Forcibly forward selected messages ignoring the host match, then log 'Yes' or 'Credentials...'."""
        msgs = invocation.getSelectedMessages()
        if not msgs:
            print("DEBUG: No messages selected in context menu.")
            return

        api_key = API_KEY
        token   = getattr(self, "_token", "")

        for msg in msgs:
            try:
                if not api_key or not token:
                    self._logRequestInTable(msg, "Credentials are not set")
                else:
                    request_str = self._helpers.bytesToString(msg.getRequest())
                    response_str = self._helpers.bytesToString(msg.getResponse())
                    url, port, pratocol = msg.getUrl(), msg.getPort(), msg.getProtocol()
                    print("DEBUG: request url", url, port, pratocol)
                    self._forward_request(api_key, token, request_str, response_str,
                                          url, port, pratocol)
                    # Because we forcibly forward, mark it 'Yes'
                    print("DEBUG: logreq1")
                    self._logRequestInTable(msg, True)
            except Exception as e:
                print("DEBUG: context menu forward =>", e)
                self._logRequestInTable(msg, False)

    def actionPerformed(self, event):
        source = event.getSource()
        if source == self._saveBtn:
            self._saveSettings()
        elif source == self._statusButton:
            self._pauseOrUnpauseScan()
        elif source == self._recheckButton:
            self._checkScanStatus()
        elif source == self._cleanButton:
            print("DEBUG: Clean button clicked => clearing table rows.")
            self._tableModel.setRowCount(0)
        elif source == self._InterceptIs:
            if self._InterceptIsStatus:
                self._InterceptIs.setText("Interception is OFF")
                self._InterceptIsStatus = False
            else:
                self._InterceptIs.setText("Interception is ON")
                self._InterceptIsStatus = True
        elif source == self._checkBox:
            # If the user toggled the checkbox, update self.just_forwarded
            self.just_forwarded = self._checkBox.isSelected()
            print("DEBUG: just_forwarded is now %s" % self.just_forwarded)
        else:
            print("DEBUG: Unknown action source =>", source)

    def _saveSettings(self):
        global API_KEY, SCAN_TOKEN

        # 1) Read user input
        self._api_key = self._apiKeyField.getText().strip()
        if self._api_key.strip(WILDCARD_REGEX) == "":
            self._api_key = API_KEY
            changed = False
        else:
            API_KEY = self._api_key
            changed = True
            self._apiKeyField.setText(8 * WILDCARD_REGEX)

        self._token = self._tokenField.getText().strip()
        if SCAN_TOKEN != self._token:
            SCAN_TOKEN = self._token
            changed_st = True
        else:
            changed_st = False


        target_raw = self._targetField.getText().strip()
        target_raw = target_raw.replace(" ", "")

        if not target_raw:
            target_raw = WILDCARD_REGEX

        if target_raw == WILDCARD_REGEX:
            self._targetRegex = None
        else:
            self._targetRegex = self._wildcard_to_regex(target_raw)

        try:
            # Build the JSON body
            json_body = '{"apiKey":"%s","token":"%s"}' % (self._api_key, self._token)

            # 4) POST to checkCreds
            resp_str, code = self._postJson(CHECK_CREDENTIALS, json_body)
            print("DEBUG: checkCreds2 => code=%d, resp=%s" % (code, resp_str))


            if changed or changed_st:
                try:
                    if code < 400 and json.loads(resp_str).get("Data") == "True":
                        message = LOGIN_SUCCESSFUL
                    else:
                        message = LOGIN_FAILED
                except:
                    message = LOGIN_FAILED
            else:
                message = TARGET_CHANGED
            self._checkScanStatus()
        except Exception as e:
            print("DEBUG: Exception in checkCreds3 =>", e)
            message = LOGIN_FAILED

        JOptionPane.showMessageDialog(
            self._mainPanel,
            message,
            "Info",
            JOptionPane.INFORMATION_MESSAGE
        )

        print("DEBUG: _saveSettings => key=%s token=%s target=%s => checkCreds => result=%s"
              % (self._api_key, self._token, target_raw, message))

    def _wildcard_to_regex(self, patterns):
        res = []
        for pattern in patterns.split(","):
            pattern = pattern.strip()
            if pattern.startswith("http://"):
                pattern = pattern.replace("http://", "", 1)
            elif pattern.startswith("https://"):
                pattern = pattern.replace("https://", "", 1)
            elif pattern.startswith("://"):
                pattern = pattern.replace("://", "", 1)

            if pattern.startswith("www."):
                pattern = pattern.replace("www.", "", 1)
            if "/" not in pattern:
                pattern += WILDCARD_REGEX
            escaped = ""
            for char in pattern:
                if char == WILDCARD_REGEX:
                    escaped += "."+WILDCARD_REGEX
                    print("CHECK WILDCARD REGEX=%s" % escaped)
                elif char in ".+()[]{}|^$?\\":
                    escaped += "\\" + char
                else:
                    escaped += char
            res.append("^" + escaped + "$")
        res = "(" + "|".join(res) + ")"
        print("Full Regex after parser", res)
        return re.compile(res, re.IGNORECASE)

    def _build_ui(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        inputPanel = JPanel(GridLayout(3, 2, 5, 5))
        inputPanel.add(JLabel("API Key:"))
        self._apiKeyField = JTextField("", 20)
        inputPanel.add(self._apiKeyField)

        inputPanel.add(JLabel("Scan Token:"))
        self._tokenField = JTextField("", 20)
        inputPanel.add(self._tokenField)

        inputPanel.add(JLabel("Target (e.g. *=all, example.com/dir1/*, *.xxxx.*.example.com):"))
        self._targetField = JTextField("", 20)
        inputPanel.add(self._targetField)
        panel.add(inputPanel)

        btnPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._saveBtn = JButton("Save Settings")
        self._saveBtn.addActionListener(self)
        btnPanel.add(self._saveBtn)
        panel.add(btnPanel)

        scanRow = JPanel(FlowLayout(FlowLayout.LEFT))
        self._statusLabel = JLabel("[?] Unknown scan status")
        scanRow.add(self._statusLabel)
        panel.add(scanRow)

        recheckRow = JPanel(FlowLayout(FlowLayout.LEFT))
        self._statusButton = JButton("Pause/Unpause")
        self._statusButton.addActionListener(self)
        recheckRow.add(self._statusButton)

        self._recheckButton = JButton("Re-Check")
        self._recheckButton.addActionListener(self)
        recheckRow.add(self._recheckButton)

        panel.add(recheckRow)

        tableLabel = JPanel(FlowLayout(FlowLayout.LEFT))
        tableLabel.add(JLabel("Forwarded Requests:"))
        panel.add(tableLabel)

        cPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._InterceptIs = JButton("Interception is ON")
        self._InterceptIs.addActionListener(self)
        cPanel.add(self._InterceptIs)

        self._cleanButton = JButton("Clean")
        self._cleanButton.addActionListener(self)
        cPanel.add(self._cleanButton)
        panel.add(cPanel)


        columns = ["Time", "Method", "Host", "Path", "Length", "Forwarded"]
        self._tableModel = DefaultTableModel(columns, 0)
        self._table      = JTable(self._tableModel)
        scrollPane       = JScrollPane(self._table)
        panel.add(scrollPane)

        checkPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._checkBox = JCheckBox("Just Forwarded", False)
        self._checkBox.addActionListener(self)
        checkPanel.add(self._checkBox)
        panel.add(checkPanel)

        return panel

    def _checkScanStatus(self):
        if SCAN_TOKEN.strip() == "" or API_KEY.strip() == "":
            print("DEBUG: Credentials are not set")
            self._setScanUnkown()
        print("DEBUG: _checkScanStatus -> POST JSON to", API_ALIVE_URL)

        api_key = API_KEY
        token   = getattr(self, "_token", "")
        json_body = '{"apiKey":"%s","token":"%s"}' % (api_key, token)
        try:
            resp_str, code = self._postJson(API_ALIVE_URL, json_body)
            print("DEBUG: alive => code=%d, body=%s" % (code, resp_str))
            print("DEBUG: res ->", resp_str)

            if code >= 400:
                self._setScanNotAlive()
                return

            try:
                print("DEBUG: res ->", resp_str)
                data_res = json.loads(resp_str).get("Data")
                if data_res == "In Progress":
                    self._setScanAlive()
                elif data_res == "Initiating":
                    self._setScanIsInitiating()
                elif data_res == "Paused":
                    self._setScanNotAlive()
                else:
                    self._setScanNotAlive()
            except:
                self._setScanNotAlive()
        except Exception as e:
            print("DEBUG: _checkScanStatus exception ->", e)
            self._setScanNotAlive()

    def _pauseOrUnpauseScan(self):
        if getattr(self, "_isScanAlive", False):
            self._sendPauseRequest(API_PAUSE_URL)
        else:
            self._sendPauseRequest(API_UNPAUSE_URL)
        self._checkScanStatus()

    def _sendPauseRequest(self, url_str):
        print("DEBUG: _sendPauseRequest =>", url_str)
        api_key = API_KEY
        token   = getattr(self, "_token", "")
        json_body = '{"apiKey":"%s","token":"%s"}' % (api_key, token)

        try:
            resp_str, code = self._postJson(url_str, json_body)
            print("DEBUG: pause/unpause => code=%d, resp=%s" % (code, resp_str))
        except Exception as e:
            print("DEBUG: _sendPauseRequest exception ->", e)

    def _setScanAlive(self):
        self._isScanAlive = True
        self._statusLabel.setText("[+] Scan is Alive (In Progress)")
        self._statusButton.setText("Pause")

    def _setScanNotAlive(self):
        self._isScanAlive = False
        self._statusLabel.setText("[-] Scan is not Alive (Paused)")
        self._statusButton.setText("Unpause")

    def _setScanIsInitiating(self):
        self._isScanAlive = False
        self._statusLabel.setText("[-] Scan is Initiating...")
        self._statusButton.setText("Cant Pause/Unpause")

    def _setScanUnkown(self):
        self._isScanAlive = False
        self._statusLabel.setText("[?] Unknown scan status")
        self._statusButton.setText("Cant Pause/Unpause")

    def _forward_request(self, api_key, token, request_data, response_data, url, port, protocol):
        try:
            print("DEBUG: _forward_request =>", API_FORWARD_URL, url)
            json_body = ('{"app": "burpsuite","apiKey":"%s","token":"%s","request":"%s","response":"%s", "url":"%s","port":"%s","protocol":"%s"}') % (
                api_key, token, string_to_base64(request_data),
                string_to_base64(response_data), url, port, protocol
            )
            try:
                if self._InterceptIsStatus:
                    print("Requests FORWARDED -> %s" % self._InterceptIsStatus)
                    threading.Thread(target=self._postJson, args=[API_FORWARD_URL, json_body]).start()
                else:
                    print("Requests NOT FORWARDED -> %s" % self._InterceptIsStatus)
                # resp_str, code = self._postJson(API_FORWARD_URL, json_body)

            except Exception as e:
                print("DEBUG: _forward_request exception ->", e)
        except Exception as e:
            print("DEBUG: _forward_request exception 2 ->", e)

    def _postJson(self, url_str, json_body):
        try:
            print("DEBUG: _postJson => Starting POST to '%s' with JSON body (truncated): %s..."
                  % (url_str, json_body[:150]))

            # 1. Create a URL object from the string and open a connection.
            url = URL(url_str)
            conn = url.openConnection()
            print("DEBUG: _postJson => Successfully opened connection to %s" % url_str)

            conn.setDoOutput(True)

            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")

            output_writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
            output_writer.write(json_body)
            output_writer.flush()
            output_writer.close()
            print("DEBUG: _postJson => Wrote JSON body to server.")

            code = conn.getResponseCode()
            print("DEBUG: _postJson => Server responded with HTTP status code %d" % code)

            reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
            lines = []
            line = reader.readLine()

            while line is not None:
                lines.append(line)
                line = reader.readLine()
            reader.close()

            resp_str = "\n".join(lines)
            print("DEBUG: _postJson => Response body (truncated): %s..."
                  % resp_str[:150])
            print("DEBUG: forward => code=%d, body=%s" % (code, resp_str))
            return resp_str, code
        except Exception as e:
            print("DEBUG: _postJson => %s" % e)

    def _logRequestInTable(self, messageInfo, forwarded):
        """
        'forwarded' can be True => 'Yes'
                     False => 'No'
                     or str => e.g. 'Credentials are not set'
        """
        try:
            analyzed = self._helpers.analyzeRequest(messageInfo)
            urlObj   = analyzed.getUrl()
            if urlObj:
                host   = urlObj.getHost()
                path   = urlObj.getPath()
                method = analyzed.getMethod()
                length = len(messageInfo.getRequest())
            else:
                host, path, method, length = ("N/A", "N/A", "N/A", 0)

            now = time.strftime("%H:%M:%S")

            if forwarded is True:
                forwarded_str = "Yes"
            elif forwarded is False:
                forwarded_str = "No"
                if self.just_forwarded:
                    return
            elif isinstance(forwarded, str):
                forwarded_str = forwarded
                if self.just_forwarded:
                    return
            else:
                forwarded_str = "No"

            if not self._InterceptIsStatus:
                forwarded_str = "No"
                if self.just_forwarded:
                    return

            row = [now, method, host, path, length, forwarded_str]
            self._tableModel.addRow(row)
            print("DEBUG: Logged row =>", row)

        except Exception as e:
            print("DEBUG: _logRequestInTable exception =>", e)

    def _escapeJson(self, text):
        text = text.replace("\\", "\\\\")
        text = text.replace("\"", "\\\"")
        return text


def string_to_base64(input_string):
    """
    Convert a string to its Base64 encoded version.

    :param input_string: The string to encode.
    :return: Base64 encoded string.
    """
    if input_string is None:
        return ""
    encoded_bytes = base64.b64encode(input_string.encode('utf-8'))
    return encoded_bytes.decode('utf-8')