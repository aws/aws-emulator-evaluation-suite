"""create-participant-token-empty-capabilities-list-honored."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-participant-token-empty-capabilities-list-honored"
GROUP = "data-plane"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateParticipantToken with an explicit empty capabilities list returns a token with a participantId and
    no capabilities field, rather than echoing the [PUBLISH, SUBSCRIBE] default."""
    ivsrt = ctx.client("ivs-realtime")
    stage = ivsrt.create_stage(
        name=ctx.unique_name("sim2real-ivsrt-stage-"), tags={"sim2real": "true"}
    )["stage"]
    ctx.on_cleanup(lambda: ivsrt.delete_stage(arn=stage["arn"]))

    token = ivsrt.create_participant_token(stageArn=stage["arn"], capabilities=[])[
        "participantToken"
    ]
    assert "capabilities" not in token, (
        f"capabilities unexpectedly present in response: {token.get('capabilities')!r}"
    )
    assert token["participantId"], "participantId missing from CreateParticipantToken response"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
