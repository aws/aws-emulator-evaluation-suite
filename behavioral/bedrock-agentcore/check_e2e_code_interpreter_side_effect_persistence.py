"""e2e-code-interpreter-side-effect-persistence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-code-interpreter-side-effect-persistence"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

_IDENTIFIER = "aws.codeinterpreter.v1"


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A file written by one InvokeCodeInterpreter call is read back by a later call in the same
    session; after StopCodeInterpreterSession the session is refused (ValidationException, 'Code
    interpreter session <id> is not active'), and a new session works but does not see the file.
    """
    client = ctx.client("bedrock-agentcore")
    session_id = client.start_code_interpreter_session(codeInterpreterIdentifier=_IDENTIFIER)["sessionId"]
    stopped = {"value": False}

    def _cleanup():
        if not stopped["value"]:
            client.stop_code_interpreter_session(codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_id)
    ctx.on_cleanup(_cleanup)

    marker = ctx.unique_name("sim2real-ci-persist-")
    file_path = "sim2real_data.txt"
    content = f"payload-{marker}"

    write_result = _invoke(client, session_id, "writeFiles", {
        "content": [{"path": file_path, "text": content}],
    })
    assert not write_result["isError"], write_result["text"]

    # Positive control: a later call in the SAME session sees the file that a previous call wrote.
    read_result = _invoke(client, session_id, "readFiles", {"paths": [file_path]})
    assert not read_result["isError"], read_result["text"]
    assert content in read_result["text"], read_result["text"]

    client.stop_code_interpreter_session(codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_id)
    stopped["value"] = True

    # Negative: a stopped session's sandbox (and its file) is unreachable.
    code, message = _error(lambda: client.invoke_code_interpreter(
        codeInterpreterIdentifier=_IDENTIFIER,
        sessionId=session_id,
        name="readFiles",
        arguments={"paths": [file_path]},
    ))
    assert code == "ValidationException", code
    expected = f"Code interpreter session {session_id} is not active"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control (in-file): the tool itself is fine -- a fresh session works normally.
    control_session = client.start_code_interpreter_session(codeInterpreterIdentifier=_IDENTIFIER)["sessionId"]
    ctx.on_cleanup(lambda: client.stop_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER, sessionId=control_session))
    control_result = _invoke(client, control_session, "executeCode", {
        "language": "python", "code": "print('alive')",
    })
    assert not control_result["isError"], control_result["text"]
    assert "alive" in control_result["text"], control_result["text"]

    # And the file from the terminated session did not somehow reappear in the new sandbox.
    missing = _invoke(client, control_session, "readFiles", {"paths": [file_path]})
    assert missing["isError"], missing["text"]


def _invoke(client, session_id, name, arguments):
    resp = client.invoke_code_interpreter(
        codeInterpreterIdentifier=_IDENTIFIER,
        sessionId=session_id,
        name=name,
        arguments=arguments,
    )
    text_parts = []
    is_error = False
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
        structured = result.get("structuredContent") or {}
        for key in ("stdout", "stderr"):
            if structured.get(key):
                text_parts.append(structured[key])
    return {"text": "\n".join(text_parts), "isError": is_error}


def _error(fn):
    """The (code, message) of the ClientError fn raises. An unexpected SUCCESS raises, so a
    target that keeps serving a stopped session fails naming what it returned."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
