"""
Chunked & Streaming File Ingestion
Handles large files incrementally with encoding fallback and malformed line counts.
"""

from typing import Generator, Tuple, TextIO


def stream_log_lines(file_stream: TextIO) -> Generator[Tuple[int, str], None, None]:
    """
    Generator streaming lines with 1-indexed line numbers.
    Avoids loading full gigabyte files into memory at once.
    """
    line_number = 1
    for raw_line in file_stream:
        clean_line = raw_line.rstrip("\r\n")
        yield line_number, clean_line
        line_number += 1


def read_content_with_fallback(content_bytes: bytes) -> str:
    """Decode raw bytes with utf-8 or latin-1 fallback."""
    try:
        return content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return content_bytes.decode("latin-1", errors="replace")
