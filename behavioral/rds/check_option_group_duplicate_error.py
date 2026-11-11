"""option-group-duplicate-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "option-group-duplicate-error"
GROUP = 'option_groups'
SERVICES = ['rds']

ERR_OPTION_GROUP_ALREADY_EXISTS = "OptionGroupAlreadyExistsFault"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating an option group with an existing name raises AlreadyExists, the name
    remains bound to the original group (not silently overwritten), and once the
    original is deleted the identical create succeeds again."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-og-")
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral test option group",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=name))
    try:
        rds.create_option_group(
            OptionGroupName=name,
            EngineName="mysql",
            MajorEngineVersion="8.0",
            OptionGroupDescription="duplicate",
        )
        code = message = None
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_OPTION_GROUP_ALREADY_EXISTS, (
        f"expected {ERR_OPTION_GROUP_ALREADY_EXISTS}, got {code!r}"
    )
    assert message == f"An option group named {name} already exists.", message

    # Effect-absent: the rejected duplicate must not have overwritten the original or
    # produced a second group under the same name.
    resp = rds.describe_option_groups(OptionGroupName=name)
    groups = resp["OptionGroupsList"]
    assert len(groups) == 1, f"expected exactly 1 option group named {name!r}, got {len(groups)}"
    assert groups[0]["OptionGroupDescription"] == "sim2real behavioral test option group", (
        f"description was overwritten by the rejected duplicate: {groups[0]['OptionGroupDescription']!r}"
    )

    # Restore: once the name is freed, the identical create call succeeds again. The
    # cleanup registered above deletes whatever ends up under `name`, so no second
    # registration is needed here.
    rds.delete_option_group(OptionGroupName=name)
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral test option group, recreated",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    resp = rds.describe_option_groups(OptionGroupName=name)
    groups = resp["OptionGroupsList"]
    assert len(groups) == 1, f"recreate did not restore a single group named {name!r}"
    assert groups[0]["OptionGroupDescription"] == "sim2real behavioral test option group, recreated", (
        f"recreate did not take effect: {groups[0]['OptionGroupDescription']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
