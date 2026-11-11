"""get-stage-malformed-arn-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-stage-malformed-arn-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetStage distinguishes a syntactically-malformed ARN (ValidationException) from a
    well-formed but non-existent one (ResourceNotFoundException) -- a lazy emulator that
    always returns ResourceNotFoundException for "arn missing" would fail this."""
    ivs = ctx.client("ivs-realtime")

    # Positive control: a real stage is retrievable by its real ARN.
    arn = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"), tags={"team": "sim2real"})[
        "stage"
    ]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=arn))
    got_arn = ivs.get_stage(arn=arn)["stage"]["arn"]
    assert got_arn == arn, f"expected {arn!r}, got {got_arn!r}"

    # A syntactically invalid ARN (doesn't match the stage ARN pattern at all).
    malformed = "not-an-arn-at-all"
    code_malformed, message_malformed = _error(lambda: ivs.get_stage(arn=malformed))
    assert code_malformed == "ValidationException", code_malformed
    expected_malformed = (
        "GetStage.arn does not match the required pattern "
        "^arn:aws:ivs:[a-z0-9-]+:[0-9]+:stage/[a-zA-Z0-9-]+$"
    )
    assert message_malformed == expected_malformed, message_malformed

    # A well-formed stage ARN that simply does not exist.
    well_formed_missing = arn[:-4] + "zzzz"
    code_missing, message_missing = _error(lambda: ivs.get_stage(arn=well_formed_missing))
    assert code_missing == "ResourceNotFoundException", code_missing
    assert message_missing == f"Resource: {well_formed_missing} not found", message_missing


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
