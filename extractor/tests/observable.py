import re
from pathlib import Path


def get_final_classes(ql_root: Path):
    """
    Scan .qll files and return all final class names.
    """
    final_class_re = re.compile(r"final class (\w+)")
    classes = set()

    for qll_file in ql_root.rglob("*.qll"):
        if not qll_file.is_file():
            continue
        try:
            text = qll_file.read_text(encoding="utf-8", errors="ignore")
            for match in final_class_re.findall(text):
                classes.add(match)
        except Exception as e:
            print(f"Skipping {qll_file}: {e}")

    return classes


def extract_imply_classes_from_tests(test_root: Path, known_classes: set):
    """Find `Imply <CLASS>, ...` markers in test docstrings, keeping only known classes."""
    test_func_re = re.compile(r"^\s*def\s+(test_\w+)\s*\(")
    imply_re = re.compile(r"Imply\s+([\w\s,]+)")

    results = []

    for py_file in test_root.rglob("*.py"):
        if not py_file.is_file():
            continue

        current_test = None
        inside_docstring = False
        doc_lines = []

        try:
            for line in py_file.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                line_strip = line.strip()

                # Detect start/end of docstring (""" or ''')
                if '"""' in line_strip or "'''" in line_strip:
                    if not inside_docstring:
                        inside_docstring = True
                        doc_lines = [line_strip]
                    else:
                        doc_lines.append(line_strip)
                        inside_docstring = False
                        docstring_text = "\n".join(doc_lines)
                        # Search for "Imply" inside docstring
                        match = imply_re.search(docstring_text)
                        if match:
                            classes = [cls.strip() for cls in match.group(1).split(",")]
                            for cls in classes:
                                if cls in known_classes:
                                    results.append(
                                        {
                                            "file": str(py_file),
                                            "test": current_test,
                                            "class": cls,
                                        }
                                    )
                        doc_lines = []
                    continue

                if inside_docstring:
                    doc_lines.append(line_strip)

                # Track current test function
                func_match = test_func_re.match(line)
                if func_match:
                    current_test = func_match.group(1)

        except Exception as e:
            print(f"Skipping {py_file}: {e}")

    return results


if __name__ == "__main__":
    ql_root = Path("../qlpack/1.0.0")  # adjust to your QL directory
    test_root = Path(".")  # adjust to your test directory

    final_classes = get_final_classes(ql_root)
    print(final_classes)
    matches = extract_imply_classes_from_tests(test_root, final_classes)

    for m in matches:
        print(f"{m['class']}: {m['file']}:{m['test']}")
