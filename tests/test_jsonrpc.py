import io

from grit.jsonrpc import MAX_MESSAGE_BYTES, read_message


def test_read_message_skips_blank_and_garbage():
    s = io.StringIO('{"a": 1}\n\n   \nnot json\n{"b": 2}\n')
    assert read_message(s) == {"a": 1}
    assert read_message(s) == {"b": 2}
    assert read_message(s) is None  # EOF


def test_read_message_ignores_non_object_json():
    s = io.StringIO('[1, 2, 3]\n"a string"\n{"ok": true}\n')
    assert read_message(s) == {"ok": True}


def test_read_message_skips_oversized_frame_without_buffering_whole():
    # a hostile, newline-less giant line is read in bounded chunks (each
    # unparseable -> skipped); a following valid frame is still delivered.
    s = io.StringIO("x" * 64 + '\n{"ok": 1}\n')
    assert read_message(s, max_bytes=16) == {"ok": 1}


def test_max_message_bytes_default_is_generous():
    # default must never split realistic MCP payloads
    assert MAX_MESSAGE_BYTES >= 16 * 1024 * 1024
