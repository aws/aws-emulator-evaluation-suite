"""agc-code-interpreter-filesystem-isolated-across-sessions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "agc-code-interpreter-filesystem-isolated-across-sessions"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore"]

_IDENTIFIER = "aws.codeinterpreter.v1"  # AWS-managed built-in Code Interpreter tool.


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A file written in one Code Interpreter session is invisible in a second session through
    readFiles, the shell and a directory listing, in both directions, while each session reads its
    own file back.
    """
    client = ctx.client("bedrock-agentcore")

    session_a = _start(ctx, client)
    session_b = _start(ctx, client)
    assert session_a != session_b, (
        f"two StartCodeInterpreterSession calls returned the same id {session_a!r}"
    )

    dir_a = ctx.unique_name("sim2real-ci-isoa-")
    dir_b = ctx.unique_name("sim2real-ci-isob-")
    path_a, path_b = f"{dir_a}/secret.txt", f"{dir_b}/secret.txt"
    token_a = ctx.unique_name("sim2real-secreta-")
    token_b = ctx.unique_name("sim2real-secretb-")

    # Each session writes its own file and reads it straight back: both sandboxes are live, and
    # each not-found below is therefore about the boundary rather than about a dead session.
    for session_id, path, token in ((session_a, path_a, token_a), (session_b, path_b, token_b)):
        written = _invoke(client, session_id, "writeFiles",
                          {"content": [{"path": path, "text": token}]})
        assert not written["isError"], f"writeFiles failed in {session_id!r}: {written['text']!r}"
        own = _invoke(client, session_id, "readFiles", {"paths": [path]})
        assert not own["isError"], f"a session cannot read its own file: {own['text']!r}"
        assert own["text"] == token, (
            f"session {session_id!r} read back {own['text']!r} instead of {token!r}"
        )

    # Neither session can reach the other's file, by any of the three routes into the filesystem.
    _assert_invisible(client, session_b, path_a, token_a, dir_a, session_a)
    _assert_invisible(client, session_a, path_b, token_b, dir_b, session_b)


def _start(ctx, client):
    """Start a Code Interpreter session, registering its teardown before anything else."""
    session_id = client.start_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER)["sessionId"]
    ctx.on_cleanup(lambda: client.stop_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_id))
    return session_id


def _assert_invisible(client, viewer, path, token, directory, owner):
    """*viewer* can see nothing of *owner*'s file at *path*, through any file-facing tool."""
    read = _invoke(client, viewer, "readFiles", {"paths": [path]})
    assert read["isError"], (
        f"session {viewer!r} READ session {owner!r}'s file {path!r}: {read['text']!r}"
    )
    assert token not in read["text"], (
        f"session {viewer!r} was served session {owner!r}'s content: {read['text']!r}"
    )

    shell = _invoke(client, viewer, "executeCommand", {"command": f"cat {path}"})
    assert shell["structuredContent"] is not None, f"no structuredContent: {shell!r}"
    assert shell["structuredContent"]["exitCode"] != 0, (
        f"the shell in session {viewer!r} catted session {owner!r}'s file {path!r}: "
        f"stdout={shell['structuredContent']['stdout']!r}"
    )
    assert token not in shell["structuredContent"]["stdout"], (
        f"session {viewer!r}'s shell printed session {owner!r}'s content: "
        f"{shell['structuredContent']['stdout']!r}"
    )

    listed = _invoke(client, viewer, "listFiles", {"directoryPath": directory})
    assert "secret.txt" not in listed["links"], (
        f"session {viewer!r} can list session {owner!r}'s directory {directory!r}: "
        f"{listed['links']!r}"
    )
    assert token not in listed["text"], (
        f"session {viewer!r}'s listing leaked {owner!r}'s content: {listed['text']!r}"
    )


def _invoke(client, session_id, name, arguments):
    """Drain an InvokeCodeInterpreter event stream into text, links, error flag, structuredContent.

    A tool-level failure arrives IN BAND as ``isError`` plus an explanatory text block rather than
    as an API error, and ``listFiles`` answers in a third shape again — ``resource_link`` blocks
    carrying a ``name`` and no text — so all of it is collected before anything is asserted.
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
