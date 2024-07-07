from pathlib import Path


def check_args(args) -> None:
    if len(args) == 1:
        raise Exception("No file specified")
    if len(args) > 2:
        raise Exception("Too many command line args")


def get_files_list(arg: str) -> list[Path]:
    path = Path(arg)

    if path.is_file():
        if path.suffix == ".jack":
            files = [path]

    if path.is_dir():
        files = [file for file in path.iterdir() if is_jack_file(file)]

    if len(files) == 0:
        raise Exception("No Jack files found from argument path.")
    return files


def clean_line(line):
    return line.split("//")[0].strip()


def is_jack_file(file: Path):
    return file.is_file() and file.suffix == ".jack"


def get_token_file_name(file_name: str):
    return f"{file_name[:-5]}T.xml"
