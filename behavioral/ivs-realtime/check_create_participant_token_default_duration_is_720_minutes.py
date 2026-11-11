"""create-participant-token-default-duration-is-720-minutes."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "create-participant-token-default-duration-is-720-minutes"
GROUP = "data-plane"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateParticipantToken without a duration omits duration from the response and returns an expirationTime
    about 720 minutes (the documented default) after issuance."""
    client = ctx.client("ivs-realtime")
    stage_arn = client.create_stage(
        name=ctx.unique_name("sim2real-stage"), tags={"sim2real": CHECK}
    )["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    before = datetime.now(timezone.utc)
    token = client.create_participant_token(stageArn=stage_arn)["participantToken"]
    after = datetime.now(timezone.utc)

    assert "duration" not in token, f"duration unexpectedly present in response: {token.get('duration')!r}"
    assert token["participantId"], "participantId missing from CreateParticipantToken response"
    assert token["token"], "token missing from CreateParticipantToken response"
    expiration = token["expirationTime"]
    if isinstance(expiration, str):
        expiration = datetime.fromisoformat(expiration.replace("Z", "+00:00"))

    minutes_from_before = (expiration - before).total_seconds() / 60.0
    minutes_from_after = (expiration - after).total_seconds() / 60.0
    # Allow a small tolerance for clock skew / request latency around the 720-minute mark.
    assert 715.0 <= minutes_from_after <= 720.5, (
        f"minutes_from_after={minutes_from_after!r} minutes_from_before={minutes_from_before!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
