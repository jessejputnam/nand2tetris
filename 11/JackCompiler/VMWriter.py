from typing import Literal

seg_type = Literal["CONST", "ARG", "LOCAL", "STATIC", "THIS", "THAT", "POINTER", "TEMP"]
comm_type = Literal["ADD", "SUB", "NEG", "EQ", "GT", "LT", "AND", "OR", "NOT"]


class VMWriter:
    def __init__(self, output):
        # Creates new output .vm file and prepares it for writing
        pass

    def write_push(self, segment: seg_type, index: int):
        # Writes a VM push command
        pass

    def write_pop(self, segment: seg_type, index: int):
        # Writes a VM pop command
        pass

    def write_arithmetic(self, command: comm_type):
        # Writes a VM arithemtic-logical command
        pass

    def write_label(self, label: str):
        # Writes a VM label command
        pass

    def write_goto(self, label: str):
        # Writes a VM goto command
        pass

    def write_if(self, label: str):
        # Writes a VM if-goto command
        pass

    def write_call(self, name: str, n_args: int):
        # Writes a VM call command
        pass

    def write_function(self, name: str, n_locals: int):
        # Writes a VM function command
        pass

    def write_return(self):
        # Writes a VM return command
        pass

    def close(self):
        # Closes the output file
        pass
