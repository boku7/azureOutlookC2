
class TextColors:

    def Background(text: str):
        return f"<span style=\"color: #282a36;\" >{text}</span>"

    def Forebground(text: str):
        return f"<span style=\"color: #f8f8f2;\" >{text}</span>"

    def Comment(text: str):
        return f"<span style=\"color: #6272a4;\" >{text}</span>"

    def CurrentLine(text: str):
        return f"<span style=\"color: #44475a;\" >{text}</span>"

    def Blue(text: str):
        return f"<span style=\"color: #8be9fd;\" >{text}</span>"

    def Green(text: str):
        return f"<span style=\"color: #50fa7b;\" >{text}</span>"

    def Orange(text: str):
        return f"<span style=\"color: #ffb86c;\" >{text}</span>"

    def Pink(text: str):
        return f"<span style=\"color: #ff79c6;\" >{text}</span>"

    def Purple(text: str):
        return f"<span style=\"color: #bd93f9;\" >{text}</span>"

    def Red(text: str):
        return f"<span style=\"color: #ff5555;\" >{text}</span>"

    def Yellow(text: str):
        return f"<span style=\"color: #f1fa8c;\" >{text}</span>"
