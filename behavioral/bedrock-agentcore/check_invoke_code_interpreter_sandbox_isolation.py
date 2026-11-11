"""invoke-code-interpreter-sandbox-isolation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invoke-code-interpreter-sandbox-isolation"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

_IDENTIFIER = "aws.codeinterpreter.v1"  # AWS-managed built-in Code Interpreter tool; no
# control-plane CodeInterpreter resource needs to be created first.


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Python variable set in one Code Interpreter session is read back in that session but raises
    NameError in a second session on the same tool: sessions do not share an interpreter namespace.
    """
    client = ctx.client("bedrock-agentcore")

    session_a = client.start_code_interpreter_session(codeInterpreterIdentifier=_IDENTIFIER)["sessionId"]
    ctx.on_cleanup(lambda: client.stop_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_a))

    session_b = client.start_code_interpreter_session(codeInterpreterIdentifier=_IDENTIFIER)["sessionId"]
    ctx.on_cleanup(lambda: client.stop_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_b))

    assert session_a != session_b, (session_a, session_b)

    marker = ctx.unique_name("sim2real-ci-iso-").replace("-", "_")
    var_name = f"secret_{marker}"
    secret_value = f"topsecret-{marker}"

    set_result = _invoke(client, session_a, "executeCode", {
        "language": "python",
        "code": f"{var_name} = '{secret_value}'\nprint('set-ok')",
    })
    assert not set_result["isError"], set_result["text"]

    # Positive control: the same session recalls the variable it just defined.
    readback = _invoke(client, session_a, "executeCode", {
        "language": "python",
        "code": f"print({var_name})",
    })
    assert not readback["isError"], readback["text"]
    assert secret_value in readback["text"], readback["text"]

    # A completely separate session must NOT see that variable.
    leaked = _invoke(client, session_b, "executeCode", {
        "language": "python",
        "code": f"print({var_name})",
    })
    assert leaked["isError"], (
        "expected a NameError in a fresh, isolated session, but the code executed cleanly "
        f"(result={leaked!r}) which means session state leaked across sandboxes"
    )
    assert "NameError" in leaked["text"], leaked["text"]
    assert secret_value not in leaked["text"], leaked["text"]


def _invoke(client, session_id, name, arguments):
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
            for key in ("stdout", "stderr"):
                if structured.get(key):
                    text_parts.append(structured[key])
    return {"text": "\n".join(text_parts), "isError": is_error, "structuredContent": structured}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
