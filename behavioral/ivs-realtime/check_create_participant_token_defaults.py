"""create-participant-token-defaults."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "create-participant-token-defaults"
GROUP = "state"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateParticipantToken without duration or capabilities omits both from the response, and its
    expirationTime lands about 720 minutes (the documented default) after issuance."""
    ivs = ctx.client("ivs-realtime")
    stage_arn = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"))["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=stage_arn))

    after = datetime.now(timezone.utc)
    token = ivs.create_participant_token(stageArn=stage_arn)["participantToken"]

    assert "duration" not in token, token.get("duration")
    expiration = token["expirationTime"]
    if isinstance(expiration, str):
        expiration = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
    minutes = (expiration - after).total_seconds() / 60.0
    assert 715.0 <= minutes <= 720.5, minutes
    # Capabilities, like duration, are omitted from the response entirely when not
    # explicitly requested (the server does not echo back the PUBLISH+SUBSCRIBE
    # default) -- absence here is itself the fact under test.
    assert "capabilities" not in token, token.get("capabilities")
    assert token["participantId"], "participantId missing from CreateParticipantToken response"
    assert token["token"], "token missing from CreateParticipantToken response"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
