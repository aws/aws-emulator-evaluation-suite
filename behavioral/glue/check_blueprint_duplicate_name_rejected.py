"""blueprint-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "blueprint-duplicate-name-rejected"
GROUP = "e2e"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBlueprint with a Name already in use is rejected with AlreadyExistsException and its exact
    message and leaves the original BlueprintLocation unchanged, while a fresh name creates a blueprint.
    """
    glue = ctx.client("glue")

    name = ctx.unique_name("sim2real-behav-bpdup-")
    original_location = f"s3://sim2real-behav-placeholder-bucket/{name}.zip"
    glue.create_blueprint(Name=name, BlueprintLocation=original_location, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_blueprint(Name=name))

    code, message = _error(
        lambda: glue.create_blueprint(
            Name=name, BlueprintLocation=f"s3://sim2real-behav-placeholder-bucket/{name}-conflict.zip"
        )
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code}"
    expected_message = "Blueprint with given name already exists"
    assert message == expected_message, (
        f"expected CreateBlueprint's duplicate-name message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the rejected call neither overwrote the original blueprint's
    # location nor renamed it.
    fetched = glue.get_blueprint(Name=name)["Blueprint"]
    assert fetched["Name"] == name, f"expected name {name!r}, got {fetched['Name']!r}"
    assert fetched["BlueprintLocation"] == original_location, (
        f"expected location {original_location!r} untouched, got {fetched['BlueprintLocation']!r}"
    )

    # Positive control: a fresh name still succeeds in the same run.
    good_name = ctx.unique_name("sim2real-behav-bpgood-")
    glue.create_blueprint(
        Name=good_name,
        BlueprintLocation=f"s3://sim2real-behav-placeholder-bucket/{good_name}.zip",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_blueprint(Name=good_name))

    fetched_good = glue.get_blueprint(Name=good_name)
    assert fetched_good["Blueprint"]["Name"] == good_name, (
        f"expected name {good_name!r}, got {fetched_good['Blueprint']['Name']!r}"
    )


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
