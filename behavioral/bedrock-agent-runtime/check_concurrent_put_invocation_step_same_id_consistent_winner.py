"""concurrent-put-invocation-step-same-id-consistent-winner."""
from __future__ import annotations

import datetime
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-invocation-step-same-id-consistent-winner"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """When multiple callers race to PutInvocationStep with the same invocationStepId but
    different payloads, exactly one payload wins and every subsequent read (from any
    caller) sees that same single payload -- never a mix, and never zero survivors."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session(tags={"sim2real-check": CHECK})
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    invocation_id = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_id)

    step_id = str(uuid.uuid4())
    step_time = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    racer_count = 6

    def _racer(i: int):
        from botocore.exceptions import ClientError

        payload = {"contentBlocks": [{"text": f"racer-{i}"}]}
        try:
            client.put_invocation_step(
                sessionIdentifier=session_id,
                invocationIdentifier=invocation_id,
                invocationStepId=step_id,
                invocationStepTime=step_time,
                payload=payload,
            )
            return ("ok", payload, None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    successes = [payload for status, payload, _ in results if status == "ok"]
    failures = [code for status, code, _ in results if status == "error"]
    failure_messages = [message for status, _, message in results if status == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)} (outcomes: {results})"
    )
    assert all(code == "ConflictException" for code in failures), (
        f"expected every loser to fail with ConflictException, got codes {failures}"
    )
    # AWS's message spells "Invcoation" this way.
    expected_message = (
        f"Combination of Invocation with ID {invocation_id} and Invcoation Step with ID {step_id} "
        "already exists"
    )
    assert all(message == expected_message for message in failure_messages), (
        f"expected every loser's message to be {expected_message!r}, got {failure_messages}"
    )

    stored = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )["invocationStep"]["payload"]
    assert stored in successes, "stored payload does not match any successful writer"

    # every later read is consistent with the single winner
    for _ in range(3):
        reread = client.get_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepId=step_id,
        )["invocationStep"]["payload"]
        assert reread == stored, f"reread payload {reread!r} diverged from first-observed {stored!r}"


def _safe_delete_session(client, session_id: str) -> None:
    try:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
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
