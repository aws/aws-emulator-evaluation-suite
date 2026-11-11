"""create-stage-with-participant-token-configurations."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-stage-with-participant-token-configurations"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStage mints one ParticipantToken per requested participantTokenConfiguration entry."""
    ivs = ctx.client("ivs-realtime")
    created = ivs.create_stage(
        name=ctx.unique_name("sim2real-stage-"),
        participantTokenConfigurations=[
            {"userId": "alice", "capabilities": ["PUBLISH"]},
            {"userId": "bob", "capabilities": ["SUBSCRIBE"]},
        ],
        tags={"purpose": "sim2real"},
    )
    arn = created["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=arn))

    tokens = created["participantTokens"]
    assert len(tokens) == 2, tokens
    by_user = {t["userId"]: t for t in tokens}
    assert set(by_user) == {"alice", "bob"}, by_user
    assert by_user["alice"]["capabilities"] == ["PUBLISH"], by_user["alice"]
    assert by_user["bob"]["capabilities"] == ["SUBSCRIBE"], by_user["bob"]
    # Distinct participants must get distinct participantIds.
    assert by_user["alice"]["participantId"] != by_user["bob"]["participantId"], by_user


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
