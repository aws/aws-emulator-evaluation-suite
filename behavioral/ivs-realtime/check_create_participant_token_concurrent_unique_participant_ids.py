"""create-participant-token-concurrent-unique-participant-ids."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "create-participant-token-concurrent-unique-participant-ids"
GROUP = "concurrency"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateParticipantToken calls against the same stage each get a distinct
    participantId with no collisions or errors."""
    ivsrt = ctx.client("ivs-realtime")
    stage = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-stage-"),
        tags={"sim2real-check": CHECK},
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    n = 10

    def _make(i):
        return ivsrt.create_participant_token(stageArn=stage["arn"], userId=f"racer-{i}")[
            "participantToken"
        ]

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_make, i) for i in range(n)]
        tokens = [f.result() for f in as_completed(futures)]

    assert len(tokens) == n, f"expected {n} completed token results, got {len(tokens)}"
    participant_ids = [t["participantId"] for t in tokens]
    assert len(set(participant_ids)) == n, (
        f"expected {n} unique participantIds, got {participant_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
