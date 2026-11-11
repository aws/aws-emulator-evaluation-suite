"""concurrent-end-session-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-end-session-single-winner"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers call EndSession on the same ACTIVE session at once: exactly one transitions it
    ACTIVE->ENDED, the rest get ConflictException (the session is not left in a mixed state)."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, session_id))

    racer_count = 6

    def _racer(_i: int):
        try:
            resp = client.end_session(sessionIdentifier=session_id)
            return ("ok", resp["sessionStatus"], None)
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert successes[0][1] == "ENDED", f"expected winner status ENDED, got {successes[0][1]}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} rejected racers, got {len(failures)}: {results}"
    )
    assert all(code == "ConflictException" for _, code, _ in failures), (
        f"expected every loser to get ConflictException, got {failures}"
    )
    assert all(message == "Cannot end a terminated session" for _, _, message in failures), (
        f"expected every loser's message to be 'Cannot end a terminated session', got {failures}"
    )

    fetched = client.get_session(sessionIdentifier=session_id)
    assert fetched["sessionStatus"] == "ENDED", (
        f"expected independent read to see ENDED, got {fetched['sessionStatus']}"
    )


def _safe_delete(ctx, session_id: str) -> None:
    client = ctx.client("bedrock-agent-runtime")
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
