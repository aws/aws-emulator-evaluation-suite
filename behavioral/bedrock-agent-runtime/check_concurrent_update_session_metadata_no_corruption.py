"""concurrent-update-session-metadata-no-corruption."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-update-session-metadata-no-corruption"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N racers UpdateSession the same session with mutually exclusive metadata payloads at once;
    the final GetSession metadata matches exactly ONE racer's payload in full, never a corrupted
    mix of fields from different racers (last-writer-wins, not partial merge)."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    racer_count = 6
    payloads = [{"racer": str(i), "marker": f"only-racer-{i}"} for i in range(racer_count)]

    def _racer(i: int):
        client.update_session(sessionIdentifier=session_id, sessionMetadata=payloads[i])

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        list(pool.map(_racer, range(racer_count)))

    final_metadata = client.get_session(sessionIdentifier=session_id)["sessionMetadata"]
    assert final_metadata in payloads, (
        f"final metadata {final_metadata} does not match any single racer's payload intact "
        f"-- looks like a corrupted partial merge"
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
