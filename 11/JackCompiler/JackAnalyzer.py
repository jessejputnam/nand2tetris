import sys
from pathlib import Path

from JackTokenizer import JackTokenizer
from CompilationEngine import CompilationEngine

from lib.Lib import (
    check_args,
    get_files_list,
    get_token_file_name,
    # get_parsed_file_name,
    get_vm_file_name,
)


if __name__ == "__main__":
    try:
        check_args(sys.argv)
        files: list[Path] = get_files_list(sys.argv[1])

        for file in files:
            # Tokenize file
            tokenizer = JackTokenizer(file)
            while tokenizer.has_more_tokens():
                tokenizer.advance()
                tokenizer.write_token()
            tokenizer.close()

            token_file = file.with_name(get_token_file_name(file.name))
            vm_file = file.with_name(get_vm_file_name(file.name))
            # parsed_file = file.with_name(get_parsed_file_name(file.name))

            comp_engine = CompilationEngine(token_file, vm_file)
        print("Files successfully compiled")

    # Error Catching
    except FileNotFoundError as e:
        print(f"File not found or cannot be opened: {e}")

    except IOError as e:
        print(f"An I/O error occurred while reading the file: {e}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        # traceback.print_exc()
