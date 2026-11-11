"""create-stage-participant-token-configurations-match-request."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-stage-participant-token-configurations-match-request"
GROUP = "data-plane"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStage with multiple ParticipantTokenConfigurations mints one ParticipantToken
    per configuration, each carrying that configuration's own userId/duration/capabilities
    (not a single shared default applied to all of them)."""
    client = ctx.client("ivs-realtime")
    configs = [
        {"userId": "alice", "duration": 10, "capabilities": ["PUBLISH"]},
        {"userId": "bob", "duration": 20, "capabilities": ["SUBSCRIBE"]},
    ]
    resp = client.create_stage(
        name=ctx.unique_name("sim2real-stage"),
        participantTokenConfigurations=configs,
        tags={"sim2real": "audit"},
    )
    stage_arn = resp["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    tokens = resp["participantTokens"]
    assert len(tokens) == 2, f"expected 2 participant tokens, got {len(tokens)}: {tokens}"
    by_user = {t["userId"]: t for t in tokens}
    assert set(by_user) == {"alice", "bob"}, f"expected userIds {{alice, bob}}, got {set(by_user)}"
    assert by_user["alice"]["duration"] == 10, f"alice duration: expected 10, got {by_user['alice']['duration']}"
    assert by_user["alice"]["capabilities"] == ["PUBLISH"], (
        f"alice capabilities: expected ['PUBLISH'], got {by_user['alice']['capabilities']}"
    )
    assert by_user["bob"]["duration"] == 20, f"bob duration: expected 20, got {by_user['bob']['duration']}"
    assert by_user["bob"]["capabilities"] == ["SUBSCRIBE"], (
        f"bob capabilities: expected ['SUBSCRIBE'], got {by_user['bob']['capabilities']}"
    )
    # Each participant gets a distinct server-assigned participant id.
    assert by_user["alice"]["participantId"] != by_user["bob"]["participantId"], (
        f"expected distinct participantIds, both were {by_user['alice']['participantId']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
