import sys
from pathlib import Path

from JackTokenizer import JackTokenizer
from CompliationEngine import CompilationEngine

from Lib import check_args, get_files_list, get_token_file_name, get_parsed_file_name


if __name__ == "__main__":
    try:
        check_args(sys.argv)

        files: list[Path] = get_files_list(sys.argv[1])
        for file in files:
            tokenizer: JackTokenizer = JackTokenizer(file)
            count = 0
            while tokenizer.has_more_tokens():
                count += 1
                tokenizer.advance()
                tokenizer.write_token()
            tokenizer.close()

            token_file = file.with_name(get_token_file_name(file.name))
            parsed_file = file.with_name(get_parsed_file_name(file.name))
            comp_engine: CompilationEngine = CompilationEngine(token_file, parsed_file)

    # Error Catching
    except FileNotFoundError as e:
        print(f"File not found or cannot be opened: {e}")

    except IOError as e:
        print(f"An I/O error occurred while reading the file: {e}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
