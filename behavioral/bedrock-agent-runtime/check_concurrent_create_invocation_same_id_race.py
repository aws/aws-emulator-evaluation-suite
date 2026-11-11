"""concurrent-create-invocation-same-id-race."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-invocation-same-id-race"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of 10 concurrent CreateInvocation calls with one invocationId, exactly one succeeds and echoes the
    id, the other 9 get ConflictException "Invocation with ID <id> already exists", and
    ListInvocations shows exactly one invocation for the id, with a createdAt."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"env": "sim2real-check"})["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    invocation_id = str(uuid.uuid4())
    racer_count = 10

    def _racer(_i: int):
        try:
            resp = client.create_invocation(
                sessionIdentifier=session_id, invocationId=invocation_id
            )
            return ("ok", resp["invocationId"], None)
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert successes[0][1] == invocation_id, (
        f"winner's echoed invocationId {successes[0][1]!r} != requested {invocation_id!r}"
    )
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    )
    assert all(code == "ConflictException" for _, code, _ in failures), (
        f"expected every loser to get ConflictException, got codes: {[c for _, c, _ in failures]}"
    )
    expected_message = f"Invocation with ID {invocation_id} already exists"
    assert all(message == expected_message for _, _, message in failures), (
        f"expected every loser's message to be {expected_message!r}, got: {[m for _, _, m in failures]}"
    )

    matching = [
        s
        for s in client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
        if s["invocationId"] == invocation_id
    ]
    assert len(matching) == 1, (
        f"expected exactly 1 invocation {invocation_id!r} in the session, found {len(matching)}"
    )
    assert matching[0]["createdAt"], (
        f"expected a real createdAt on the surviving invocation, got {matching[0].get('createdAt')!r}"
    )


def _safe_end_and_delete(ctx, session_id: str) -> None:
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
