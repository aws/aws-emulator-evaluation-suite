"""create-participant-token-duration-and-capabilities-recorded."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "create-participant-token-duration-and-capabilities-recorded"
GROUP = "data-plane"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateParticipantToken echoes the requested duration 45, userId, attributes and capabilities, and its
    expirationTime lands about 45 minutes after issuance, so the duration governs expiry."""
    client = ctx.client("ivs-realtime")
    stage_arn = client.create_stage(name=ctx.unique_name("sim2real-stage"))["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    before = datetime.now(timezone.utc)
    token = client.create_participant_token(
        stageArn=stage_arn,
        duration=45,
        userId="sim2real-user-abc",
        attributes={"role": "host", "team": "blue"},
        capabilities=["PUBLISH", "SUBSCRIBE"],
    )["participantToken"]
    after = datetime.now(timezone.utc)

    assert token["duration"] == 45, token.get("duration")
    assert token["userId"] == "sim2real-user-abc", token.get("userId")
    assert token["attributes"] == {"role": "host", "team": "blue"}, token.get("attributes")
    assert sorted(token["capabilities"]) == ["PUBLISH", "SUBSCRIBE"], token.get("capabilities")
    assert token["token"], "token string missing/empty"
    assert token["participantId"], "participantId missing/empty"

    expiration = token["expirationTime"]
    if isinstance(expiration, str):
        expiration = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
    minutes_from_after = (expiration - after).total_seconds() / 60.0
    minutes_from_before = (expiration - before).total_seconds() / 60.0
    # The requested 45-minute duration must actually govern expirationTime, not just
    # be echoed in the response struct -- allow a small tolerance for call latency.
    assert 44.0 <= minutes_from_after <= 45.5, (
        f"minutes_from_after={minutes_from_after!r} minutes_from_before={minutes_from_before!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
