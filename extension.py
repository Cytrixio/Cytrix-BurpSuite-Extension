# -*- coding: utf-8 -*-
"""
CytrixExtension_PostJSON_FullLogging.py
---------------------------------------
1. Calls api.cytrix.io (alive, pause, unpause, forward) with POST JSON.
2. Logs ALL requests in the table:
   - "Yes" if forwarded,
   - "No" if host mismatch,
   - "Credentials are not set" if missing API key or token.
3. Adds a "Clean" button to remove all rows from the table.
4. Right-click "Send request to Cytrix" forcibly forwards if credentials exist,
   ignoring the host pattern.

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

API_KEY = ""
SCAN_TOKEN = ""
BASE_URL_API = "https://api.cytrix.io/Interception_"
API_ALIVE_URL   = BASE_URL_API + "GetScanStatus"
API_PAUSE_URL   = BASE_URL_API + "TargetPause"
API_UNPAUSE_URL = BASE_URL_API + "TargetUnPause"
API_FORWARD_URL = BASE_URL_API + "UploadFile"
CHECK_CREDENTIALS = BASE_URL_API + "CheckCreds"

class BurpExtender(IBurpExtender, ITab, IHttpListener, ActionListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        callbacks.setExtensionName("Cytrix")

        self._mainPanel = self._build_ui()
        callbacks.addSuiteTab(self)

        # Initialize our new variable
        self.just_forwarded = False

        # Register
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self._checkScanStatus()
        print("DEBUG: Extension loaded. Logs 'Yes', 'No', or 'Credentials not set' in the table, plus 'Clean' button.")

    #
    # ITab
    #
    def getTabCaption(self):
        return "Cytrix"

    def getUiComponent(self):
        return self._mainPanel

    #
    # IHttpListener
    #
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

    #
    # IContextMenuFactory
    #
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

    #
    # ActionListener
    #
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
        elif source == self._checkBox:
            # If the user toggled the checkbox, update self.just_forwarded
            self.just_forwarded = self._checkBox.isSelected()
            print("DEBUG: just_forwarded is now %s" % self.just_forwarded)
        else:
            print("DEBUG: Unknown action source =>", source)

    #
    # Save
    #
    def _saveSettings(self):
        global API_KEY, SCAN_TOKEN
        """
        1. Read API Key, Token, and Target from the text fields.
        2. If the Target is empty, treat it as '*'.
        3. Convert the Target into a wildcard regex (unless '*').
        4. POST JSON to 'https://api.cytrix.io/checkCreds' with { "api_key", "token" }.
        5. If response is 'ok', show 'login successful'; otherwise 'login failed'.
        """

        # 1) Read user input
        self._api_key = self._apiKeyField.getText().strip()
        if self._api_key.strip("*") == "":
            self._api_key = API_KEY
            changed = False
        else:
            API_KEY = self._api_key
            changed = True
            self._apiKeyField.setText(8 * "*")

        self._token = self._tokenField.getText().strip()
        if SCAN_TOKEN != self._token:
            SCAN_TOKEN = self._token
            changed_st = True
        else:
            changed_st = False


        target_raw = self._targetField.getText().strip()
        target_raw = target_raw.replace(" ", "")

        # 2) If target is empty, treat as '*'
        if not target_raw:
            target_raw = "*"

        # 3) Build or clear the regex
        if target_raw == "*":
            self._targetRegex = None
        else:
            self._targetRegex = self._wildcard_to_regex(target_raw)



        # Now we check the credentials against https://api.cytrix.io/checkCreds
        # using our existing _postJson method.
        try:
            # Build the JSON body
            json_body = '{"apiKey":"%s","token":"%s"}' % (self._api_key, self._token)

            # 4) POST to checkCreds
            resp_str, code = self._postJson(CHECK_CREDENTIALS, json_body)
            print("DEBUG: checkCreds2 => code=%d, resp=%s" % (code, resp_str))


            if changed or changed_st:
                try:
                    if code < 400 and json.loads(resp_str).get("Data") == "True":
                        message = "login successful"
                    else:
                        message = "login failed"
                except:
                    message = "login failed"
            else:
                message = "Target Changed"
            self._checkScanStatus()
        except Exception as e:
            # If we get an exception (network error, etc.), treat as fail
            print("DEBUG: Exception in checkCreds3 =>", e)
            message = "login failed"

        # Show a dialog with the result
        JOptionPane.showMessageDialog(
            self._mainPanel,
            message,
            "Info",
            JOptionPane.INFORMATION_MESSAGE
        )

        # Log what happened
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
                pattern += "*"
            escaped = ""
            for char in pattern:
                if char == '*':
                    escaped += ".*"
                elif char in ".+()[]{}|^$?\\":
                    escaped += "\\" + char
                else:
                    escaped += char
            res.append("^" + escaped + "$")
        res = "(" + "|".join(res) + ")"
        print(res, "sahar")
        return re.compile(res, re.IGNORECASE)

    #
    # Build UI
    #
    def _build_ui(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # 1) Inputs
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

        # 2) Buttons
        btnPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._saveBtn = JButton("Save Settings")
        self._saveBtn.addActionListener(self)
        btnPanel.add(self._saveBtn)
        panel.add(btnPanel)

        # 3) Scan status row
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


        # 4) Table
        tableLabel = JPanel(FlowLayout(FlowLayout.LEFT))
        tableLabel.add(JLabel("Forwarded Requests:"))
        panel.add(tableLabel)


        columns = ["Time", "Method", "Host", "Path", "Length", "Forwarded"]
        self._tableModel = DefaultTableModel(columns, 0)
        self._table      = JTable(self._tableModel)
        scrollPane       = JScrollPane(self._table)
        panel.add(scrollPane)

        # 5) Clean button row
        cPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._cleanButton = JButton("Clean")
        self._cleanButton.addActionListener(self)
        cPanel.add(self._cleanButton)
        panel.add(cPanel)

        # Create the checkbox
        checkPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._checkBox = JCheckBox("Just Forwarded", False)
        self._checkBox.addActionListener(self)
        checkPanel.add(self._checkBox)
        panel.add(checkPanel)

        return panel

    #
    # Alive / Pause / Unpause
    #
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

    #
    # Forward to https://api.cytrix.io/index.php
    #
    def _forward_request(self, api_key, token, request_data, response_data, url, port, protocol):
        try:
            print("DEBUG: _forward_request =>", API_FORWARD_URL, url)
            json_body = ('{"app": "burpsuite","apiKey":"%s","token":"%s","request":"%s","response":"%s", "url":"%s","port":"%s","protocol":"%s"}') % (
                api_key, token, string_to_base64(request_data),
                string_to_base64(response_data), url, port, protocol
            )
            try:
                threading.Thread(target=self._postJson, args=[API_FORWARD_URL, json_body]).start()
                # resp_str, code = self._postJson(API_FORWARD_URL, json_body)

            except Exception as e:
                print("DEBUG: _forward_request exception ->", e)
        except Exception as e:
            print("DEBUG: _forward_request exception 2 ->", e)
    #
    # POST JSON utility
    #
    def _postJson(self, url_str, json_body):
        try:
            """
            Send a POST request with a JSON body to the specified url_str using Java URLConnection.
    
            Steps:
            1. Open a connection to the URL.
            2. Enable output mode to allow sending POST data.
            3. Set the request method to POST and the Content-Type header to 'application/json'.
            4. Write the JSON body to the server.
            5. Read the response status and body from the server.
            6. Return the server's response body and HTTP status code to the caller.
            """
            print("DEBUG: _postJson => Starting POST to '%s' with JSON body (truncated): %s..."
                  % (url_str, json_body[:150]))

            # 1. Create a URL object from the string and open a connection.
            url = URL(url_str)
            conn = url.openConnection()
            print("DEBUG: _postJson => Successfully opened connection to %s" % url_str)

            # 2. Enable output so we can send POST data in the body.
            conn.setDoOutput(True)

            # 3. We want a POST request, and we set the Content-Type to JSON.
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")

            # 4. Write the JSON body to the server using an OutputStreamWriter.
            output_writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
            output_writer.write(json_body)
            output_writer.flush()
            output_writer.close()
            print("DEBUG: _postJson => Wrote JSON body to server.")

            # 5. Read the server's HTTP response code.
            code = conn.getResponseCode()
            print("DEBUG: _postJson => Server responded with HTTP status code %d" % code)

            # 5a. Next, we read the response body from the server.
            reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
            lines = []
            line = reader.readLine()
            # Keep reading until no more lines are available.
            while line is not None:
                lines.append(line)
                line = reader.readLine()
            reader.close()


            # Convert the list of lines into a single string.
            resp_str = "\n".join(lines)
            print("DEBUG: _postJson => Response body (truncated): %s..."
                  % resp_str[:150])
            print("DEBUG: forward => code=%d, body=%s" % (code, resp_str))
            # 6. Return the server's response body and the status code to the caller.
            return resp_str, code
        except Exception as e:
            print("DEBUG: _postJson => %s" % e)

    #
    # Insert row in table -> "Yes", "No", or "Credentials are not set"
    #
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

            row = [now, method, host, path, length, forwarded_str]
            self._tableModel.addRow(row)
            print("DEBUG: Logged row =>", row)

        except Exception as e:
            print("DEBUG: _logRequestInTable exception =>", e)

    def _escapeJson(self, text):
        # Minimal JSON escaping for quotes/backslashes
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