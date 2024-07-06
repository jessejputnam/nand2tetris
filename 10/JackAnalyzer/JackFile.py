class JackFile:
    def __init__(self, file_path: str):
        self.path = file_path
        self.path_xml = f"{file_path[:-5]}.xml"
        self.xml = ""

    def get_jack_path(self) -> str:
        return self.path

    def get_xml_path(self) -> str:
        return self.path_xml

    def get_xml(self) -> str:
        return self.xml
