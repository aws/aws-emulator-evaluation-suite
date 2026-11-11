"""update-stage-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-stage-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStage rejects a name containing characters outside [a-zA-Z0-9-_] with
    ValidationException, the stage's name is left completely unchanged (the bad update
    never applied), and a well-formed rename in the same call shape succeeds."""
    client = ctx.client("ivs-realtime")
    original_name = ctx.unique_name("sim2real-stage")
    stage_arn = client.create_stage(name=original_name)["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    error = _client_error(lambda: client.update_stage(arn=stage_arn, name="bad name! not allowed"))
    assert error["Code"] == "ValidationException", f"expected ValidationException, got {error!r}"
    assert error["Message"] == "UpdateStage.name does not match the required pattern ^[a-zA-Z0-9-_]*$", (
        f"unexpected UpdateStage name-pattern message: {error['Message']!r}"
    )

    # Effect absent: the name on record is still the original one.
    unchanged = client.get_stage(arn=stage_arn)["stage"]["name"]
    assert unchanged == original_name, f"expected name unchanged at {original_name!r}, got {unchanged!r}"

    # Positive control: a well-formed name change is accepted and persists.
    new_name = original_name + "-renamed"
    updated = client.update_stage(arn=stage_arn, name=new_name)["stage"]
    assert updated["name"] == new_name, f"expected update to return {new_name!r}, got {updated['name']!r}"
    persisted = client.get_stage(arn=stage_arn)["stage"]["name"]
    assert persisted == new_name, f"expected persisted name {new_name!r}, got {persisted!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ValidationException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
