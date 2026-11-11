"""copy-option-group-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-option-group-round-trip"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyOptionGroup produces an independent option group whose options match the source."""
    rds = ctx.client("rds")

    source_name = ctx.unique_name("sim2real-og-src-")
    rds.create_option_group(
        OptionGroupName=source_name,
        EngineName="mariadb",
        MajorEngineVersion="10.6",
        OptionGroupDescription="sim2real source option group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_option_group_if_present(rds, source_name))
    rds.modify_option_group(
        OptionGroupName=source_name,
        OptionsToInclude=[{"OptionName": "MARIADB_AUDIT_PLUGIN"}],
        ApplyImmediately=True,
    )

    target_name = ctx.unique_name("sim2real-og-copy-")
    rds.copy_option_group(
        SourceOptionGroupIdentifier=source_name,
        TargetOptionGroupIdentifier=target_name,
        TargetOptionGroupDescription="sim2real copied option group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_option_group(OptionGroupName=target_name))

    source = rds.describe_option_groups(OptionGroupName=source_name)["OptionGroupsList"][0]
    copy = rds.describe_option_groups(OptionGroupName=target_name)["OptionGroupsList"][0]

    assert copy["OptionGroupName"] != source["OptionGroupName"], (
        f"copy shares source's name: {copy['OptionGroupName']}"
    )
    assert copy["OptionGroupArn"] != source["OptionGroupArn"], (
        f"copy shares source's ARN: {copy['OptionGroupArn']}"
    )
    assert copy["EngineName"] == source["EngineName"] == "mariadb", (
        f"expected both engines mariadb, got source={source['EngineName']} copy={copy['EngineName']}"
    )
    assert copy["MajorEngineVersion"] == source["MajorEngineVersion"] == "10.6", (
        f"expected both versions 10.6, got source={source['MajorEngineVersion']} copy={copy['MajorEngineVersion']}"
    )
    src_options = sorted(o["OptionName"] for o in source["Options"])
    copy_options = sorted(o["OptionName"] for o in copy["Options"])
    assert src_options == copy_options == ["MARIADB_AUDIT_PLUGIN"], (
        f"expected both option lists ['MARIADB_AUDIT_PLUGIN'], got source={src_options} copy={copy_options}"
    )

    # Deleting the source must not affect the independently-copied option group.
    rds.delete_option_group(OptionGroupName=source_name)
    not_found_message = f"Specified OptionGroupName: {source_name} not found."
    try:
        rds.describe_option_groups(OptionGroupName=source_name)
        raise AssertionError("source option group still describable after delete")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "OptionGroupNotFoundFault", (
            f"expected OptionGroupNotFoundFault, got {e.response['Error']['Code']}"
        )
        assert e.response["Error"]["Message"] == not_found_message, (
            f"expected message {not_found_message!r}, got {e.response['Error']['Message']!r}"
        )

    # The dead id is unusable, not just unlistable: a mutation against it fails too.
    try:
        rds.modify_option_group(
            OptionGroupName=source_name,
            OptionsToInclude=[{"OptionName": "MARIADB_AUDIT_PLUGIN"}],
            ApplyImmediately=True,
        )
        raise AssertionError("modify_option_group succeeded against a deleted option group")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "OptionGroupNotFoundFault", (
            f"expected OptionGroupNotFoundFault, got {e.response['Error']['Code']}"
        )
        assert e.response["Error"]["Message"] == not_found_message, (
            f"expected message {not_found_message!r}, got {e.response['Error']['Message']!r}"
        )

    still_there = rds.describe_option_groups(OptionGroupName=target_name)["OptionGroupsList"][0]
    assert still_there["OptionGroupName"] == target_name, (
        f"expected copied group {target_name}, got {still_there['OptionGroupName']}"
    )
    assert [o["OptionName"] for o in still_there["Options"]] == ["MARIADB_AUDIT_PLUGIN"], (
        f"copied group options drifted after source delete: {still_there['Options']}"
    )


def _delete_option_group_if_present(rds, name: str) -> None:
    """Teardown: the body deletes the source group itself, so not-found here is expected."""
    try:
        rds.delete_option_group(OptionGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "OptionGroupNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
