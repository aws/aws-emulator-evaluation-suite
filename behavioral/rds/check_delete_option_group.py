"""delete-option-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-option-group"
GROUP = 'option_groups'
SERVICES = ['rds']

ERR_OPTION_GROUP_NOT_FOUND = "OptionGroupNotFoundFault"

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteOptionGroup removes the group; Describe raises error, a repeat delete on the
    same dead id fails the same way, and the freed name is reusable."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-og-")
    tags_kw = dict(Tags=[{"Key": "sim2real", "Value": "delete-option-group"}])
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral test option group",
        **tags_kw,
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=name))
    rds.delete_option_group(OptionGroupName=name)
    code = message = None
    try:
        rds.describe_option_groups(OptionGroupName=name)
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_OPTION_GROUP_NOT_FOUND, (
        f"expected {ERR_OPTION_GROUP_NOT_FOUND}, got {code!r}"
    )
    assert message == f"Specified OptionGroupName: {name} not found.", message

    # A second delete on the now-dead id must fail the same way, not resurrect it or
    # silently no-op.
    code = message = None
    try:
        rds.delete_option_group(OptionGroupName=name)
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    assert code == ERR_OPTION_GROUP_NOT_FOUND, (
        f"repeat delete on dead id: expected {ERR_OPTION_GROUP_NOT_FOUND}, got {code!r}"
    )
    assert message == f"Specified OptionGroupName: {name} not found.", message

    # The freed name is reusable.
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral test option group",
        **tags_kw,
    )
    recreated = rds.describe_option_groups(OptionGroupName=name).get("OptionGroupsList", [])
    assert recreated and recreated[0]["OptionGroupName"] == name, (
        f"expected the freed name {name!r} to be reusable, got {recreated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
