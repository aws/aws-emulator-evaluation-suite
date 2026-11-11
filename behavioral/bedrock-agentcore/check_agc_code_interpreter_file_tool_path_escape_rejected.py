"""agc-code-interpreter-file-tool-path-escape-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "agc-code-interpreter-file-tool-path-escape-rejected"
GROUP = "rejected-input"
SERVICES = ["bedrock-agentcore"]

_IDENTIFIER = "aws.codeinterpreter.v1"  # AWS-managed built-in Code Interpreter tool.

# One escape attempt per file tool, each paired with the in-sandbox path that is the positive
# control for exactly that tool. A traversal and an absolute path are both tried, because a
# validator that only rejects "../" leaves the wider hole open.
_ESCAPES = [
    ("readFiles", {"paths": ["../../etc/hostname"]}),
    ("readFiles", {"paths": ["/etc/hostname"]}),
    ("writeFiles", {"content": [{"path": "../sim2real-escape.txt", "text": "escaped"}]}),
    ("writeFiles", {"content": [{"path": "/tmp/sim2real-escape.txt", "text": "escaped"}]}),
    ("removeFiles", {"paths": ["../../etc/hostname"]}),
    ("listFiles", {"directoryPath": "../.."}),
]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """readFiles, writeFiles, removeFiles and listFiles each refuse a `../` traversal and an
    absolute path in band, naming path traversal, with no out-of-sandbox content or file left
    behind, while the same four tools succeed on an in-sandbox relative path in the same session.
    """
    client = ctx.client("bedrock-agentcore")

    session = client.start_code_interpreter_session(codeInterpreterIdentifier=_IDENTIFIER)
    session_id = session["sessionId"]
    ctx.on_cleanup(lambda: client.stop_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_id))

    marker = ctx.unique_name("sim2real-ci-esc-")
    inside = f"{marker}/inside.txt"
    body = f"in-sandbox {marker}"

    # Positive controls first: all four tools work in this session, on a path that does not escape.
    ok_write = _invoke(client, session_id, "writeFiles",
                       {"content": [{"path": inside, "text": body}]})
    assert not ok_write["isError"], f"positive control writeFiles failed: {ok_write['text']!r}"
    ok_read = _invoke(client, session_id, "readFiles", {"paths": [inside]})
    assert not ok_read["isError"], f"positive control readFiles failed: {ok_read['text']!r}"
    assert ok_read["text"] == body, f"positive control read back {ok_read['text']!r}, not {body!r}"
    ok_list = _invoke(client, session_id, "listFiles", {"directoryPath": marker})
    assert not ok_list["isError"], f"positive control listFiles failed: {ok_list['text']!r}"
    assert "inside.txt" in ok_list["links"], (
        f"positive control listFiles did not name the file it just wrote: {ok_list['links']!r}"
    )

    # The escapes. Each is refused in band, and names traversal rather than a missing file: an
    # emulator that answers "File ../../etc/hostname not found" has a different security model,
    # and that difference is the whole point of asserting on the reason.
    for tool, arguments in _ESCAPES:
        result = _invoke(client, session_id, tool, arguments)
        assert result["isError"], (
            f"{tool} ACCEPTED an out-of-sandbox path {arguments!r} instead of refusing it; "
            f"result={result!r}"
        )
        assert "path traversal" in result["text"].lower(), (
            f"{tool} refused {arguments!r} for the wrong reason: {result['text']!r}"
        )
        # Nothing else came back with it: the refusal is the entire response, so no file content
        # and no directory listing from outside the sandbox was served alongside the error.
        assert result["text"].startswith("Error executing tool "), (
            f"{tool} returned content as well as a refusal for {arguments!r}: {result['text']!r}"
        )
        assert not result["links"], (
            f"{tool} listed out-of-sandbox entries alongside its refusal of {arguments!r}: "
            f"{result['links']!r}"
        )

    # The write escapes left nothing behind outside the working directory.
    escaped = _invoke(client, session_id, "executeCommand", {
        "command": "ls -1 /tmp/sim2real-escape.txt ../sim2real-escape.txt 2>&1 | sort -u",
    })
    assert escaped["structuredContent"] is not None, f"no structuredContent: {escaped!r}"
    assert "No such file" in escaped["structuredContent"]["stdout"], (
        f"a refused writeFiles still created a file outside the sandbox working directory: "
        f"{escaped['structuredContent']!r}"
    )

    still_there = _invoke(client, session_id, "readFiles", {"paths": [inside]})
    assert not still_there["isError"], (
        f"the in-sandbox file became unreadable after the refused calls: {still_there['text']!r}"
    )
    assert still_there["text"] == body, (
        f"the in-sandbox file changed to {still_there['text']!r}, expected {body!r}"
    )


def _invoke(client, session_id, name, arguments):
    """Drain an InvokeCodeInterpreter event stream into text, links, error flag, structuredContent.

    A tool-level failure is reported IN BAND as ``isError`` plus an explanatory text block, not as
    an API error, so both halves have to be collected before anything can be asserted. ``listFiles``
    answers in a third shape again — ``resource_link`` blocks carrying a ``name`` and no text at
    all — so its entries are collected separately rather than folded into the text.
    """
    resp = client.invoke_code_interpreter(
        codeInterpreterIdentifier=_IDENTIFIER,
        sessionId=session_id,
        name=name,
        arguments=arguments,
    )
    text_parts = []
    links = []
    is_error = False
    structured = None
    for event in resp["stream"]:
        result = event.get("result")
        if not result:
            continue
        if result.get("isError"):
            is_error = True
        for block in result.get("content") or []:
            if block.get("text"):
                text_parts.append(block["text"])
            if block.get("type") == "resource_link":
                links.append(block.get("name") or block.get("uri"))
            resource = block.get("resource") or {}
            if resource.get("text"):
                text_parts.append(resource["text"])
        if result.get("structuredContent"):
            structured = result["structuredContent"]
    return {"text": "\n".join(text_parts), "links": links, "isError": is_error,
            "structuredContent": structured}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
