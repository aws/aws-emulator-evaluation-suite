"""put-invocation-step-duplicate-stepid-serialized."""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-duplicate-stepid-serialized"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent PutInvocationStep calls with one invocationStepId: exactly one wins, the other gets
    ConflictException, and the stored payload is the winner's; a separate step id still succeeds."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _cleanup_session(ctx, session_id))
    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    step_id = str(uuid.uuid4())
    step_time = datetime.now(timezone.utc)
    barrier = threading.Barrier(2)
    results: dict[str, tuple[str, Any]] = {}

    def _put(tag: str) -> None:
        barrier.wait()
        try:
            resp = client.put_invocation_step(
                sessionIdentifier=session_id,
                invocationIdentifier=invocation_id,
                invocationStepId=step_id,
                invocationStepTime=step_time,
                payload={"contentBlocks": [{"text": f"payload-from-{tag}"}]},
            )
            results[tag] = ("ok", resp)
        except Exception as exc:  # noqa: BLE001
            results[tag] = ("error", _error_code(exc))

    threads = [threading.Thread(target=_put, args=(tag,)) for tag in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    outcomes = {tag: results[tag][0] for tag in ("a", "b")}
    successes = [tag for tag, kind in outcomes.items() if kind == "ok"]
    failures = [tag for tag, kind in outcomes.items() if kind == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got outcomes={outcomes}"
    assert len(failures) == 1, f"expected exactly one loser, got outcomes={outcomes}"
    assert results[failures[0]][1] == "ConflictException", (
        f"expected ConflictException for the loser, got {results[failures[0]][1]!r}"
    )

    winner_tag = successes[0]
    stored = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )["invocationStep"]
    # the loser's write left no trace: the persisted payload is exactly the
    # winner's, never the loser's and never a merge of both.
    expected_text = f"payload-from-{winner_tag}"
    actual_text = stored["payload"]["contentBlocks"][0]["text"]
    assert actual_text == expected_text, (
        f"stored payload should be the winner's ({expected_text!r}), got {actual_text!r}"
    )

    # positive control, in the same file: a fresh, non-colliding
    # invocationStepId on the same invocation still succeeds normally.
    control_step_id = str(uuid.uuid4())
    control_resp = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=control_step_id,
        invocationStepTime=step_time,
        payload={"contentBlocks": [{"text": "control-payload"}]},
    )
    assert control_resp["invocationStepId"] == control_step_id, (
        f"expected echoed invocationStepId {control_step_id!r}, got {control_resp['invocationStepId']!r}"
    )
    control_stored = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=control_step_id,
    )["invocationStep"]
    control_text = control_stored["payload"]["contentBlocks"][0]["text"]
    assert control_text == "control-payload", (
        f"expected control payload 'control-payload', got {control_text!r}"
    )


def _error_code(exc: Exception) -> str | None:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code")
    return None


def _cleanup_session(ctx, session_id: str) -> None:
    client = ctx.client("bedrock-agent-runtime")
    try:
        client.end_session(sessionIdentifier=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        client.delete_session(sessionIdentifier=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
