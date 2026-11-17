"""copy-option-group-onto-existing-target-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-option-group-onto-existing-target-name-rejected"
GROUP = "option_groups"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyOptionGroup onto a TargetOptionGroupIdentifier that already names a different option
    group is rejected, that existing group is left untouched, and copying to a free name
    right after still succeeds.
    """
    rds = ctx.client("rds")

    source_name = ctx.unique_name("sim2real-behav-ogsrc-")
    rds.create_option_group(
        OptionGroupName=source_name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral check source",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=source_name))

    taken_name = ctx.unique_name("sim2real-behav-ogtaken-")
    rds.create_option_group(
        OptionGroupName=taken_name,
        EngineName="mariadb",
        MajorEngineVersion="10.6",
        OptionGroupDescription="sim2real behavioral check pre-existing target",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=taken_name))

    code, message = _error(
        lambda: rds.copy_option_group(
            SourceOptionGroupIdentifier=source_name,
            TargetOptionGroupIdentifier=taken_name,
            TargetOptionGroupDescription="sim2real should not land",
        )
    )
    assert code == "OptionGroupAlreadyExistsFault", (
        f"expected OptionGroupAlreadyExistsFault copying onto the taken name {taken_name!r}, "
        f"got {code!r}: {message!r}"
    )
    assert message == f"An option group named {taken_name} already exists.", (
        f"unexpected message for the taken-name rejection: {message!r}"
    )

    # Effect-absent: the pre-existing target still carries its own engine and description,
    # not the source's.
    untouched = rds.describe_option_groups(OptionGroupName=taken_name)["OptionGroupsList"][0]
    assert untouched["EngineName"] == "mariadb", (
        f"the rejected copy must leave {taken_name!r}'s engine alone, got {untouched['EngineName']!r}"
    )
    assert untouched["OptionGroupDescription"] == "sim2real behavioral check pre-existing target", (
        f"the rejected copy must leave {taken_name!r}'s description alone, "
        f"got {untouched['OptionGroupDescription']!r}"
    )

    # Restore: the identical source copies cleanly onto a name nothing holds.
    free_name = ctx.unique_name("sim2real-behav-ogfree-")
    rds.copy_option_group(
        SourceOptionGroupIdentifier=source_name,
        TargetOptionGroupIdentifier=free_name,
        TargetOptionGroupDescription="sim2real behavioral check copy",
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=free_name))
    copied = rds.describe_option_groups(OptionGroupName=free_name)["OptionGroupsList"][0]
    assert copied["EngineName"] == "mysql", (
        f"expected the successful copy to carry the source's engine mysql, got {copied['EngineName']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
