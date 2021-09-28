from PyQt6.QtCore import *
from PyQt6.QtWidgets import *

class Token(object):
    def __init__(self):
        self.refresh = ""
        self.access = ""
        self.userName = ""
        self.tenantId = ""
        self.clientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
        self.userAgent = "Mozilla"
        self.resource = "https://graph.microsoft.com"
        self.grantType = "refresh_token"
        self.scope = "openid"

class StartDialogUI(object):
    def __init__(self, Dialog):
        self.Dialog = Dialog
        self.StartButtonPressed = False
        self.Error = False

    def setupUi(self):
        self.Dialog.setWindowTitle("Azure Outlook C2")
        self.Dialog.setStyleSheet(
            "QDialog {background-color: #282a36;color: #f8f8f2;} QLineEdit { background-color: #44475a;color: #f8f8f2; }QTextEdit { background-color: #44475a;color: #f8f8f2; } QPushButton {border: 1px solid #bd93f9;border-radius: 2px;background-color: #bd93f9;color: #282a36;padding-top: 10px;padding-bottom: 10px; } QPushButton:pressed {font-size: 13px;border: 1px solid #bd93f9;border-radius: 2px;background-color: #282a36;color: #f8f8f2;padding-top: 30px;padding-bottom: 30px;} QLabel {color: #f8f8f2;}")
        if not self.Dialog.objectName():
            self.Dialog.setObjectName(u"Dialog")
        self.Dialog.resize(497, 286)
        self.gridLayout = QGridLayout(self.Dialog)
        self.gridLayout.setObjectName(u"gridLayout")
        self.textEdit = QTextEdit(self.Dialog)
        self.textEdit.setObjectName(u"textEdit")

        self.gridLayout.addWidget(self.textEdit, 3, 1, 1, 4)

        self.horizontalSpacer_4 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.gridLayout.addItem(self.horizontalSpacer_4, 5, 1, 1, 1)

        self.label = QLabel(self.Dialog)
        self.label.setObjectName(u"label")

        self.gridLayout.addWidget(self.label, 1, 0, 1, 5)

        self.label_3 = QLabel(self.Dialog)
        self.label_3.setObjectName(u"label_3")

        self.gridLayout.addWidget(self.label_3, 3, 0, 1, 1)

        self.label_2 = QLabel(self.Dialog)
        self.label_2.setObjectName(u"label_2")

        self.gridLayout.addWidget(self.label_2, 2, 0, 1, 1)

        self.horizontalSpacer_5 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.gridLayout.addItem(self.horizontalSpacer_5, 5, 3, 1, 1)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.gridLayout.addItem(self.horizontalSpacer, 4, 2, 1, 1)

        self.horizontalSpacer_3 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.gridLayout.addItem(self.horizontalSpacer_3, 5, 0, 1, 1)

        self.pushButton = QPushButton(self.Dialog)
        self.pushButton.setObjectName(u"pushButton")
        self.pushButton.clicked.connect(self.onStartButton)

        self.gridLayout.addWidget(self.pushButton, 5, 2, 1, 1)

        self.lineEdit = QLineEdit(self.Dialog)
        self.lineEdit.setObjectName(u"lineEdit")

        self.gridLayout.addWidget(self.lineEdit, 2, 1, 1, 4)

        self.horizontalSpacer_2 = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.gridLayout.addItem(self.horizontalSpacer_2, 5, 4, 1, 1)

        QMetaObject.connectSlotsByName(self.Dialog)

    # setupUi

    def retranslateUi(self):
        self.label.setText(QCoreApplication.translate("Dialog",
                                                      u"<html><head/><body><p align=\"center\"><span style=\" font-size:18pt;\">Azure Outlook C2</span></p></body></html>",
                                                      None))
        self.label_3.setText(
            QCoreApplication.translate("Dialog", u"<html><head/><body><p>Refresh Token:</p></body></html>", None))
        self.label_2.setText(QCoreApplication.translate("Dialog", u"Tenant Id:", None))
        self.pushButton.setText(QCoreApplication.translate("Dialog", u"Start", None))

    def onStartButton(self):
        closeDialog = False
        self.StartButtonPressed = True

        critbox = QMessageBox()
        critbox.setWindowTitle("Error")
        critbox.setStyleSheet("QMessageBox { background-color: #282a36; color: #f8f8f2 } QMessageBox QLabel { color: #f8f8f2 } QPushButton {border: 1px solid #bd93f9;border-radius: 2px;background-color: #bd93f9;color: #282a36; padding: 5px; padding-left: 15px; padding-right: 15px } QPushButton:pressed {font-size: 13px;border: 1px solid #bd93f9;border-radius: 2px;background-color: #282a36;color: #f8f8f2;}")
        critbox.setIcon(QMessageBox.Icon.Critical)
        critbox.setStandardButtons(QMessageBox.StandardButton.Ok)

        if len(self.textEdit.toPlainText()) == 0:
            self.Error = True
            critbox.setText("No Refresh Token set")
            critbox.exec()

        if len(self.lineEdit.text()) == 0:
            self.Error = True
            critbox.setText("No Tenant Id set")
            critbox.exec()

        if not closeDialog:
            self.Dialog.close()

    def StartWindow(self) -> bool:
        self.setupUi()
        self.retranslateUi()
        self.Dialog.exec()

        if self.StartButtonPressed and not self.Error:
            return True
        else:
            return False

    def GetTokenInfo(self) -> Token:
        token = Token()

        token.tenantId = self.lineEdit.text()
        token.refresh = self.textEdit.toPlainText()

        return token