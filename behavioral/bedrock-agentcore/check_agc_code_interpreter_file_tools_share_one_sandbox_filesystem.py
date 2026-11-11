"""agc-code-interpreter-file-tools-share-one-sandbox-filesystem."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "agc-code-interpreter-file-tools-share-one-sandbox-filesystem"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

_IDENTIFIER = "aws.codeinterpreter.v1"  # AWS-managed built-in Code Interpreter tool; no
# control-plane CodeInterpreter resource has to be created first.


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A file written by writeFiles reads back byte-identically through readFiles, executeCode
    (Python) and executeCommand (shell) in the same session, and removeFiles makes it disappear
    from all three: the tools share one sandbox filesystem.
    """
    client = ctx.client("bedrock-agentcore")

    session = client.start_code_interpreter_session(codeInterpreterIdentifier=_IDENTIFIER)
    session_id = session["sessionId"]
    ctx.on_cleanup(lambda: client.stop_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_id))

    # A per-run payload, so nothing can pass by echoing a canned body, and a relative path
    # inside the sandbox's own working directory (the file tools reject absolute paths). The
    # body's token is deliberately NOT the path's: a not-found message quotes the path back, so
    # a token shared between the two would make "the content is gone" unassertable.
    marker = ctx.unique_name("sim2real-ci-fs-")
    path = f"{marker}/payload.txt"
    body_token = ctx.unique_name("sim2real-ci-body-")
    body = f"line-one {body_token}\nline-two {body_token}"

    written = _invoke(client, session_id, "writeFiles",
                      {"content": [{"path": path, "text": body}]})
    assert not written["isError"], f"writeFiles failed: {written['text']!r}"

    # View 1 — the readFiles tool returns the bytes as a resource.
    read = _invoke(client, session_id, "readFiles", {"paths": [path]})
    assert not read["isError"], f"readFiles failed after writeFiles: {read['text']!r}"
    assert read["text"] == body, (
        f"readFiles returned {read['text']!r}, not the {len(body)}-byte body {body!r} that "
        f"writeFiles accepted"
    )

    # View 2 — the Python interpreter opens the same path and reports the exact byte count.
    code = (
        f"data = open({path!r}, 'rb').read()\n"
        f"print('len', len(data))\n"
        f"print('body', data.decode())"
    )
    py = _invoke(client, session_id, "executeCode", {"language": "python", "code": code})
    assert not py["isError"], f"executeCode could not open the written file: {py['text']!r}"
    assert f"len {len(body.encode())}" in py["text"], (
        f"executeCode saw a different size than writeFiles was given "
        f"({len(body.encode())} bytes): {py['text']!r}"
    )
    assert body_token in py["text"], (
        f"executeCode read back {py['text']!r}, expected it to contain {body_token!r}"
    )

    # View 3 — the shell sees it too, and reports a zero exit status for `cat`.
    sh = _invoke(client, session_id, "executeCommand", {"command": f"cat {path}"})
    assert not sh["isError"], f"executeCommand could not cat the written file: {sh['text']!r}"
    assert sh["structuredContent"] is not None, f"no structuredContent on executeCommand: {sh!r}"
    assert sh["structuredContent"]["exitCode"] == 0, (
        f"`cat {path}` exited {sh['structuredContent']['exitCode']!r} in the same session that "
        f"just wrote it; stderr={sh['structuredContent'].get('stderr')!r}"
    )
    assert body_token in sh["structuredContent"]["stdout"], (
        f"shell stdout was {sh['structuredContent']['stdout']!r}, expected it to contain "
        f"{body_token!r}"
    )

    # The deletion propagates to every view: the tool, the interpreter and the shell.
    removed = _invoke(client, session_id, "removeFiles", {"paths": [path]})
    assert not removed["isError"], f"removeFiles failed: {removed['text']!r}"

    gone = _invoke(client, session_id, "readFiles", {"paths": [path]})
    assert gone["isError"], (
        f"readFiles still served {path!r} after removeFiles reported success: {gone!r}"
    )
    assert body_token not in gone["text"], (
        f"readFiles leaked the removed file's content: {gone['text']!r}"
    )

    py_gone = _invoke(client, session_id, "executeCode", {
        "language": "python",
        "code": f"import os\nprint('exists', os.path.exists({path!r}))",
    })
    assert not py_gone["isError"], f"executeCode failed unexpectedly: {py_gone['text']!r}"
    assert "exists False" in py_gone["text"], (
        f"the interpreter can still see the removed file: {py_gone['text']!r}"
    )

    sh_gone = _invoke(client, session_id, "executeCommand", {"command": f"cat {path}"})
    assert sh_gone["structuredContent"] is not None, f"no structuredContent: {sh_gone!r}"
    assert sh_gone["structuredContent"]["exitCode"] != 0, (
        f"`cat {path}` still succeeded after removeFiles: "
        f"stdout={sh_gone['structuredContent']['stdout']!r}"
    )


def _invoke(client, session_id, name, arguments):
    """Drain an InvokeCodeInterpreter event stream into text, error flag and structuredContent.

    The tool result arrives as a stream of events rather than a single body, and a tool-level
    failure is reported IN BAND as ``isError`` with an explanatory text block rather than as an
    API error — so both have to be collected before anything can be asserted.
    """
    resp = client.invoke_code_interpreter(
        codeInterpreterIdentifier=_IDENTIFIER,
        sessionId=session_id,
        name=name,
        arguments=arguments,
    )
    text_parts = []
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
            resource = block.get("resource") or {}
            if resource.get("text"):
                text_parts.append(resource["text"])
        if result.get("structuredContent"):
            structured = result["structuredContent"]
    return {"text": "\n".join(text_parts), "isError": is_error, "structuredContent": structured}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
