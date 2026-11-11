"""code-interpreter-async-task-converges-and-stop-task-cancels."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "code-interpreter-async-task-converges-and-stop-task-cancels"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore"]

# The AWS-managed built-in code interpreter; usable with no prior CreateCodeInterpreter call.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-start-session.html
_IDENTIFIER = "aws.codeinterpreter.v1"

_QUICK_SLEEP_S = 8
_SLOW_SLEEP_S = 120
_TERMINAL = frozenset({"completed", "canceled", "failed"})


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An asynchronously started sandbox command is observably non-terminal, converges to
    completed no sooner than its own sleep, and leaves the file it wrote readable, while a second
    task stopped mid-flight ends canceled or failed, never completed, and never writes its file."""
    client = ctx.client("bedrock-agentcore")

    session_id = client.start_code_interpreter_session(
        codeInterpreterIdentifier=_IDENTIFIER,
        name=ctx.unique_name("simparity-task-")[:100],
        sessionTimeoutSeconds=900,
    )["sessionId"]
    ctx.on_cleanup(
        lambda: client.stop_code_interpreter_session(
            codeInterpreterIdentifier=_IDENTIFIER, sessionId=session_id
        )
    )

    marker = ctx.unique_name("simparity-async-").replace("-", "_")
    quick_out = f"{marker}_quick.txt"
    slow_out = f"{marker}_slow.txt"

    written = _invoke(
        client,
        session_id,
        "writeFiles",
        {
            "content": [
                {
                    "path": f"{marker}_quick.sh",
                    "text": f"sleep {_QUICK_SLEEP_S}\nprintf '%s' {marker} > {quick_out}\n",
                },
                {
                    "path": f"{marker}_slow.sh",
                    "text": f"sleep {_SLOW_SLEEP_S}\nprintf '%s' {marker} > {slow_out}\n",
                },
            ]
        },
    )
    assert not written["isError"], (
        f"writeFiles failed to stage the two task scripts: {written['text']!r}"
    )

    # ---- Leg 1: the async task really is async, and really runs.
    started = time.monotonic()
    submit = _invoke(
        client, session_id, "startCommandExecution", {"command": f"sh {marker}_quick.sh"}
    )
    assert not submit["isError"], (
        f"startCommandExecution was refused: {submit['text']!r}"
    )
    structured = submit["structuredContent"]
    assert structured, (
        "startCommandExecution returned no structuredContent, so there is no taskId to poll: "
        f"{submit!r}"
    )
    task_id = structured["taskId"]
    submit_status = structured["taskStatus"]
    # The discriminator for a target that runs commands synchronously: a task whose script
    # sleeps for 8s cannot already be terminal at submit time.
    assert submit_status not in _TERMINAL, (
        f"startCommandExecution reported taskStatus {submit_status!r} immediately, but the "
        f"script sleeps {_QUICK_SLEEP_S}s before doing anything — a terminal status here means "
        "the target executed the command synchronously instead of scheduling a task"
    )

    quick_final = _poll_until(
        lambda: _invoke(client, session_id, "getTask", {"taskId": task_id}),
        lambda r: (r["structuredContent"] or {}).get("taskStatus") in _TERMINAL,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"task {task_id} reached a terminal taskStatus",
    )
    quick_structured = quick_final["structuredContent"]
    quick_status = quick_structured["taskStatus"]
    assert quick_status == "completed", (
        f"task {task_id} finished as {quick_status!r}, expected 'completed' "
        f"(stderr={quick_structured.get('stderr')!r})"
    )
    elapsed = time.monotonic() - started
    # The task cannot finish before its own sleep, so an instant completion is not a real run.
    assert elapsed >= _QUICK_SLEEP_S, (
        f"the task reported completed after only {elapsed:.1f}s, but its script sleeps "
        f"{_QUICK_SLEEP_S}s before it can finish"
    )
    assert quick_structured["exitCode"] == 0, (
        f"task {task_id} completed with exitCode {quick_structured['exitCode']!r}, expected 0 "
        f"(stderr={quick_structured.get('stderr')!r})"
    )

    # The terminal evidence for leg 1 is an independent read through a DIFFERENT tool —
    # readFiles, not getTask — proving the async task really touched the sandbox filesystem.
    quick_read = _invoke(client, session_id, "readFiles", {"paths": [quick_out]})
    assert not quick_read["isError"], (
        f"readFiles could not read {quick_out!r}, which the completed task should have written: "
        f"{quick_read['text']!r}"
    )
    assert marker in quick_read["text"], (
        f"{quick_out!r} does not contain the marker {marker!r} the task wrote into it: "
        f"{quick_read['text']!r}"
    )

    # ---- Leg 2: stopTask cancels, and the cancelled work is structurally unsatisfiable.
    cancel_started = time.monotonic()
    slow_submit = _invoke(
        client, session_id, "startCommandExecution", {"command": f"sh {marker}_slow.sh"}
    )
    assert not slow_submit["isError"], (
        f"startCommandExecution was refused for the long task: {slow_submit['text']!r}"
    )
    slow_task_id = slow_submit["structuredContent"]["taskId"]

    stopped = _invoke(client, session_id, "stopTask", {"taskId": slow_task_id})
    assert not stopped["isError"], (
        f"stopTask was refused for the running task {slow_task_id!r}: {stopped['text']!r}"
    )

    slow_final = _poll_until(
        lambda: _invoke(client, session_id, "getTask", {"taskId": slow_task_id}),
        lambda r: (r["structuredContent"] or {}).get("taskStatus") in _TERMINAL,
        timeout_s=60.0,
        interval_s=3.0,
        description=f"stopped task {slow_task_id} reached a terminal taskStatus",
    )
    slow_status = slow_final["structuredContent"]["taskStatus"]
    # AWS ends a stopped task as canceled or as failed; either way its work did not finish.
    assert slow_status in ("canceled", "failed"), (
        f"the stopped task {slow_task_id!r} finished as {slow_status!r}, expected 'canceled' or "
        "'failed'. A target with no cancellation reports 'completed' or leaves it running"
    )
    cancel_elapsed = time.monotonic() - cancel_started
    # The other side of the clock: cancelling must not have waited out the task's own sleep.
    assert cancel_elapsed < _SLOW_SLEEP_S, (
        f"cancelling took {cancel_elapsed:.1f}s, which is at least the {_SLOW_SLEEP_S}s the "
        "task would have slept anyway — that is indistinguishable from letting it run"
    )

    # The absence is unsatisfiable by construction: the file only exists after a
    # 120s sleep and we are far inside that window. Leg 1 is the positive control on the same
    # wiring, proving a task's writes DO become readable, so this emptiness is evidence.
    slow_read = _invoke(client, session_id, "readFiles", {"paths": [slow_out]})
    assert slow_read["isError"], (
        f"readFiles succeeded on {slow_out!r} after its task was cancelled "
        f"{cancel_elapsed:.1f}s in, well before the {_SLOW_SLEEP_S}s sleep that precedes the "
        f"write: {slow_read['text']!r}"
    )
    # Second independent observable for the same absence.
    listing = _invoke(client, session_id, "listFiles", {"directoryPath": "."})
    assert not listing["isError"], f"listFiles('.') failed: {listing['text']!r}"
    assert slow_out not in listing["text"], (
        f"the cancelled task's output file {slow_out!r} appears in the directory listing: "
        f"{listing['text'][:400]!r}"
    )

    # Terminal read: the completed task's file is STILL there after the cancellation, so the
    # cancel was scoped to its own task and did not reset the sandbox.
    final_read = _invoke(client, session_id, "readFiles", {"paths": [quick_out]})
    assert not final_read["isError"], (
        f"the completed task's file {quick_out!r} became unreadable after another task was "
        f"cancelled: {final_read['text']!r}"
    )
    assert marker in final_read["text"], (
        f"{quick_out!r} no longer contains {marker!r} after the cancellation: "
        f"{final_read['text']!r}"
    )


# ===== helpers =====


def _invoke(client, session_id, name, arguments):
    """One InvokeCodeInterpreter call, with its event stream drained into a flat result.

    CodeInterpreterStreamOutput is a streaming union whose `result` member carries the tool
    outcome, so the stream must be consumed before anything can be asserted.
    """
    resp = client.invoke_code_interpreter(
        codeInterpreterIdentifier=_IDENTIFIER,
        sessionId=session_id,
        name=name,
        arguments=arguments,
    )
    text_parts: list[str] = []
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
            if block.get("name"):
                text_parts.append(block["name"])
        if result.get("structuredContent"):
            structured = result["structuredContent"]
            for key in ("stdout", "stderr"):
                if structured.get(key):
                    text_parts.append(structured[key])
    return {"text": "\n".join(text_parts), "isError": is_error, "structuredContent": structured}


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout and never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not observed within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
