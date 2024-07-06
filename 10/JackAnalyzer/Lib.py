import os


def check_args(args):
    if len(args) == 1:
        raise Exception("No file specified")
    if len(args) > 2:
        raise Exception("Too many command line args")


def get_program_and_files(path):
    program_name = path if os.path.isdir(path) else path[:-3]

    if os.path.isfile(path):
        if not path[-3:] == ".jack":
            raise Exception("Unrecognized file type -- Requires .vm extension")
        program_name = path[:-3]
        return [program_name, [path]]

    if os.path.isdir(path):
        dir_path = f"{path}" if path[-1] == "/" else f"{path}/"
        program_name = f"{dir_path}/{dir_path[:-1].split("/")[-1]}"
        l = [f"{dir_path}{file}" for file in os.listdir(path) if file[-3:] == ".vm"]
        if len(l) == 0:
            raise Exception("No vm files found in directory")

        files = []
        for file in l:
            is_sys = file.split('/')[-1] == 'Sys.vm'
            files.insert(0, file) if is_sys else files.append(file)

    return [program_name, files]


def clean_line(line):
    return line.split("//")[0].strip()


def end_program():
    return "(ENDPROGRAM)\n@ENDPROGRAM\n0;JMP\n"
