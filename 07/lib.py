import os


def check_args(args):
    if len(args) == 1:
        raise Exception("No file specified")
    if len(args) > 2:
        raise Exception("Too many command line args")


def get_program_and_files(path):
    program_name = path if os.path.isdir(path) else path[:-3]
    files = os.listdir(path) if os.path.isdir(path) else [path]
    for file in files:
        if not file[-3:] == ".vm":
            raise Exception("Unrecognized file type -- Requires .vm extension")
    return [program_name, files]


def is_comment(line):
    return not line or line[:2] == "//"


def end_program():
    return "(ENDPROGRAM)\n@ENDPROGRAM\n0;JMP\n"
