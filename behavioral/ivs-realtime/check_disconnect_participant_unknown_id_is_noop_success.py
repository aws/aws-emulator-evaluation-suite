"""disconnect-participant-unknown-id-is-noop-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disconnect-participant-unknown-id-is-noop-success"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisconnectParticipant with an unknown participantId on a stage that never had a session answers 200 as a
    no-op, and the stage stays readable."""
    ivsrt = ctx.client("ivs-realtime")
    stage = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-stage-"), tags={"team": "sim2real"}
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    resp = ivsrt.disconnect_participant(
        stageArn=stage["arn"], participantId="no-such-participant"
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected DisconnectParticipant on an unknown id to no-op with 200, got {status}"

    # Positive control: the stage itself is unaffected and still reachable.
    reread_arn = ivsrt.get_stage(arn=stage["arn"])["stage"]["arn"]
    assert reread_arn == stage["arn"], f"expected stage {stage['arn']!r} unaffected, get_stage returned {reread_arn!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
