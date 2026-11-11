"""modify-option-group-empty."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-option-group-empty"
GROUP = 'option_groups'
SERVICES = ['rds']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyOptionGroup with no options raises InvalidParameterValue, after a real option
    (MARIADB_AUDIT_PLUGIN, which needs no port or VPC security group) applies and reads back,
    so the rejection is not one that refuses every ModifyOptionGroup call."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-og-")
    rds.create_option_group(
        OptionGroupName=name,
        EngineName="mysql",
        MajorEngineVersion="8.0",
        OptionGroupDescription="sim2real behavioral test option group",
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=name))

    rds.modify_option_group(
        OptionGroupName=name,
        ApplyImmediately=True,
        OptionsToInclude=[
            {
                "OptionName": "MARIADB_AUDIT_PLUGIN",
                "OptionSettings": [{"Name": "SERVER_AUDIT_EVENTS", "Value": "CONNECT,QUERY"}],
            }
        ],
    )
    resp = rds.describe_option_groups(OptionGroupName=name)
    names = [o["OptionName"] for o in resp["OptionGroupsList"][0]["Options"]]
    assert "MARIADB_AUDIT_PLUGIN" in names, (
        f"positive control failed: expected MARIADB_AUDIT_PLUGIN applied, got {names!r}"
    )

    try:
        rds.modify_option_group(
            OptionGroupName=name,
            OptionsToInclude=[],
            OptionsToRemove=[],
            ApplyImmediately=True,
        )
    except ClientError as _e:
        code = _e.response.get("Error", {}).get("Code")
        message = _e.response.get("Error", {}).get("Message")
    else:
        raise AssertionError("ModifyOptionGroup with no options to add, modify or remove was accepted")
    assert code == "InvalidParameterValue", (
        f"Expected InvalidParameterValue for empty modify, got {code!r}"
    )
    expected = "At least one option must be added, modified, or removed."
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
