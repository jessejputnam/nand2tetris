import os
from JackFile import JackFile


class Analyzer:
    def __init__(self, arg: str):
        self.files: list[JackFile] = []

        if os.path.isfile(arg):
            self.add_jack_file(arg)

        if os.path.isdir(arg):
            dir_path = f"{arg}" if arg[-1] == "/" else f"{arg}/"
            for file_name in os.listdir(arg):
                self.add_jack_file(f"${dir_path}{file_name}")

        if len(self.files) == 0:
            raise Exception("No Jack files found from argument path.")

    def add_jack_file(self, file: str):
        if file[-5:] == ".jack":
            file = JackFile(file)
            self.files.append(file)

    def test_files(self) -> str:
        for file in self.files:
            print(file.get_jack_path())
            print(file.get_xml_path())
            print("-------")

    def write_output(self):
        if len(self.output):
            raise Exception("No xml output found.")

        for file in self.output:
            with open(f"{file.get_name()}.xml", "w") as wf:
                wf.write(file.get_xml())
