"""create-participant-token-nonexistent-stage-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-participant-token-nonexistent-stage-not-found"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateParticipantToken against a syntactically-valid but nonexistent stageArn
    (in the caller's own account/region) is rejected with ResourceNotFoundException,
    and a real stage in the same account still works fine (positive control)."""
    client = ctx.client("ivs-realtime")
    bogus_arn = f"arn:aws:ivs:{ctx.region}:{ctx.account}:stage/{ctx.unique_name('missing').replace('_', '-')}"

    error = _client_error(lambda: client.create_participant_token(stageArn=bogus_arn))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent stageArn, got {error!r}"
    )
    assert error.get("Message") == f"Resource: {bogus_arn} not found", error

    real_stage_arn = client.create_stage(name=ctx.unique_name("sim2real-stage"))["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=real_stage_arn))
    token = client.create_participant_token(stageArn=real_stage_arn)["participantToken"]
    assert token["participantId"], f"positive control returned no participantId: {token!r}"
    assert token["token"], f"positive control returned no signed token: {token!r}"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
