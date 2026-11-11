"""code-interpreter-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "code-interpreter-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A code interpreter goes CREATING to READY; after DeleteCodeInterpreter GetCodeInterpreter answers
    ResourceNotFoundException rather than a DELETED status, and a second delete is refused with
    ResourceNotFoundException "Code interpreter with ID <id> does not exist"."""
    bac = ctx.client("bedrock-agentcore-control")
    name = _safe_name(ctx, "sim2realci")

    create_resp = bac.create_code_interpreter(
        name=name, networkConfiguration={"networkMode": "SANDBOX"}
    )
    ci_id = create_resp["codeInterpreterId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_code_interpreter(codeInterpreterId=ci_id)))

    state = _poll_until(
        lambda: _tolerant_get(lambda: bac.get_code_interpreter(codeInterpreterId=ci_id)),
        lambda r: r is not None and r["status"] != "CREATING",
        timeout_s=180.0,
    )
    assert state["status"] == "READY", f"unexpected terminal status {state['status']!r}"

    bac.delete_code_interpreter(codeInterpreterId=ci_id)
    state2 = _poll_until(
        lambda: _tolerant_get(lambda: bac.get_code_interpreter(codeInterpreterId=ci_id)),
        lambda r: r is None or r["status"] not in ("DELETING",),
        timeout_s=180.0,
    )
    assert state2 is None, (
        "expected an independent GetCodeInterpreter to 404 with ResourceNotFoundException "
        f"once deleted (real AWS never reports a terminal DELETED status), got {state2!r}"
    )

    second_delete_code, second_delete_message = _error_detail(
        lambda: bac.delete_code_interpreter(codeInterpreterId=ci_id)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"deleting an already-deleted code interpreter id should 404 the same way, "
        f"got error code {second_delete_code!r}"
    )
    expected_message = f"Code interpreter with ID {ci_id} does not exist"
    assert second_delete_message == expected_message, (
        f"expected message {expected_message!r}, got {second_delete_message!r}"
    )


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _tolerant_get(fn):
    try:
        return fn()
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
