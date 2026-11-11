"""invoke-code-interpreter-clear-context-resets-the-namespace."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invoke-code-interpreter-clear-context-resets-the-namespace"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

# The AWS-managed built-in code interpreter; usable with no prior CreateCodeInterpreter call.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-start-session.html
_IDENTIFIER = "aws.codeinterpreter.v1"


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """clearContext=True on executeCode discards the interpreter namespace of the session it is
    called in: a variable that the same session could read a moment earlier is gone, while the
    interpreter itself still works and can bind new names."""
    client = ctx.client("bedrock-agentcore")

    session_id = client.start_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER,
        name=ctx.unique_name("simparity-clearctx-")[:100],
        sessionTimeoutSeconds=900,
    )["sessionId"]
    ctx.on_cleanup(
        lambda: client.stop_code_interpreter_session(
            codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_id
        )
    )

    marker = ctx.unique_name("simparity-ctx-").replace("-", "_")
    first_var = f"before_{marker}"
    first_value = f"kept-{marker}"
    second_var = f"after_{marker}"
    second_value = f"rebound-{marker}"

    # Leg 1 — bind a name.
    bound = _execute(client, session_id, f"{first_var} = '{first_value}'\nprint('bound-ok')")
    assert not bound["isError"], f"binding {first_var} failed: {bound['text']!r}"
    assert "bound-ok" in bound["text"], (
        f"the binding call produced no stdout marker: {bound['text']!r}"
    )

    # Leg 2 — POSITIVE CONTROL, and the whole premise of leg 3: without clearContext the SAME
    # session recalls what it just bound. If this fails, the session has no persistent namespace
    # and leg 3's absence would prove nothing.
    recalled = _execute(client, session_id, f"print({first_var})")
    assert not recalled["isError"], (
        f"the same session could not read back {first_var} it had just bound: {recalled['text']!r}"
    )
    assert first_value in recalled["text"], (
        f"reading {first_var} printed {recalled['text']!r}, expected it to contain "
        f"{first_value!r}"
    )

    # Leg 3 — the discriminator. Exactly one thing changes: clearContext=True. A target that
    # stores the flag and ignores it prints the value here and passes nothing.
    cleared = _execute(client, session_id, f"print({first_var})", clear_context=True)
    assert cleared["isError"], (
        f"executeCode with clearContext=True still resolved {first_var!r} and returned "
        f"{cleared['text']!r}; clearing the context must discard the session's bindings"
    )
    assert "NameError" in cleared["text"], (
        f"expected a NameError for {first_var!r} after clearContext=True, got "
        f"{cleared['text']!r}"
    )
    assert first_value not in cleared["text"], (
        f"the cleared call leaked the pre-clear value {first_value!r}: {cleared['text']!r}"
    )

    # Leg 4 — the reset is a namespace reset, not a dead session: the interpreter still executes
    # and can bind a new name. This is what separates "cleared the context" from "the session
    # broke", which would otherwise produce the same isError in leg 3.
    rebound = _execute(
        client, session_id, f"{second_var} = '{second_value}'\nprint({second_var})"
    )
    assert not rebound["isError"], (
        f"the session could not bind a new name after clearContext=True, so leg 3's failure may "
        f"have been a broken session rather than a context reset: {rebound['text']!r}"
    )
    assert second_value in rebound["text"], (
        f"binding and printing {second_var} produced {rebound['text']!r}, expected it to contain "
        f"{second_value!r}"
    )

    # Leg 5 — terminal read: the consequence of the clear persists. The pre-clear name is still
    # gone in a later, un-cleared call, while the post-clear name is present in the same call.
    # (The interpreter namespace has no independent reader, so the
    # assertion is on the consequence — what is now usable and what is now unusable.)
    final = _execute(
        client,
        session_id,
        (
            f"print({second_var})\n"
            f"print({first_var})\n"
        ),
    )
    assert final["isError"], (
        f"{first_var!r} came back after the context was cleared and a new name was bound: "
        f"{final['text']!r}"
    )
    assert second_value in final["text"], (
        f"the post-clear binding {second_var!r} did not survive into the next call: "
        f"{final['text']!r}"
    )
    assert first_value not in final["text"], (
        f"the pre-clear value {first_value!r} reappeared: {final['text']!r}"
    )
    assert "NameError" in final["text"], (
        f"expected the surviving failure for {first_var!r} to still be a NameError: "
        f"{final['text']!r}"
    )



def _execute(client, session_id, code, *, clear_context=None):
    """One executeCode invocation, with its event stream drained into a flat result.

    CodeInterpreterStreamOutput is a streaming union whose `result` member carries the tool
    outcome, so the stream must be consumed before anything can be asserted.
    """
    arguments = {"language": "python", "code": code}
    if clear_context is not None:
        arguments["clearContext"] = clear_context
    resp = client.invoke_code_interpreter(
        codeInterpreterIdentifier=_IDENTIFIER,
        sessionId=session_id,
        name="executeCode",
        arguments=arguments,
    )
    text_parts: list[str] = []
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
