"""Turn a percent-cell .py file into a .ipynb: `python scripts/py_to_ipynb.py in.py out.ipynb`."""

import json
import sys
from typing import Any


def convert(src: str) -> dict[str, Any]:
    cells: list[dict[str, Any]] = []
    kind = "code"
    buf: list[str] = []

    def flush() -> None:
        body = "\n".join(buf).strip("\n")
        if not body:
            return
        if kind == "markdown":
            body = "\n".join(
                line[2:] if line.startswith("# ") else line.lstrip("#")
                for line in body.splitlines()
            )
            cells.append(
                {
                    "cell_type": "markdown",
                    "metadata": {},
                    "source": body.splitlines(True),
                }
            )
        else:
            body = "\n".join(
                line[2:] if line.startswith("# !") else line
                for line in body.splitlines()
            )
            cells.append(
                {
                    "cell_type": "code",
                    "metadata": {},
                    "execution_count": None,
                    "outputs": [],
                    "source": body.splitlines(True),
                }
            )

    for line in src.splitlines():
        if line.startswith("# %%"):
            flush()
            kind, buf = ("markdown" if "[markdown]" in line else "code"), []
        else:
            buf.append(line)
    flush()
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "name": "python3",
                "display_name": "Python 3",
                "language": "python",
            }
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


if __name__ == "__main__":
    with open(sys.argv[1]) as src, open(sys.argv[2], "w") as dst:
        json.dump(convert(src.read()), dst, indent=1)
