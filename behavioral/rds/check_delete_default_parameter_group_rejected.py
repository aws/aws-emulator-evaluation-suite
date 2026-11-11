"""delete-default-parameter-group-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-default-parameter-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDBParameterGroup on a default (AWS-managed) parameter group is rejected; the default
    group survives the attempt, while deleting a genuinely user-created group in the same call
    session succeeds (positive control)."""
    rds = ctx.client("rds")

    families = rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True)["DBEngineVersions"]
    family = families[0]["DBParameterGroupFamily"]
    default_name = f"default.{family}"
    # Sanity: the default group must actually exist and be describable before we rely on it.
    before = rds.describe_db_parameter_groups(DBParameterGroupName=default_name)["DBParameterGroups"][0]
    assert before["DBParameterGroupName"] == default_name, (
        f"expected describe to echo {default_name!r}, got {before['DBParameterGroupName']!r}"
    )

    code, message = _error_code(lambda: rds.delete_db_parameter_group(DBParameterGroupName=default_name))
    assert code == "InvalidDBParameterGroupState", f"unexpected error code: {code!r}"
    assert message == f"Default DBParameterGroup cannot be deleted: {default_name}", f"unexpected message: {message!r}"

    # Effect absent: the default group is still there, completely unaffected by the failed delete.
    after = rds.describe_db_parameter_groups(DBParameterGroupName=default_name)["DBParameterGroups"][0]
    assert after["DBParameterGroupName"] == default_name, (
        f"default group should still be named {default_name!r} after the rejected delete, "
        f"got {after['DBParameterGroupName']!r}"
    )
    assert after["DBParameterGroupFamily"] == family, (
        f"default group family should remain {family!r} after the rejected delete, "
        f"got {after['DBParameterGroupFamily']!r}"
    )

    # Positive control: a genuinely user-created parameter group CAN be deleted in this same
    # session, proving the rejection above is specific to "default" groups, not a blanket failure.
    custom_name = ctx.unique_name("sim2real-rds-pg-ctrl-")
    rds.create_db_parameter_group(
        DBParameterGroupName=custom_name,
        DBParameterGroupFamily=family,
        Description="sim2real control group",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _safety_net_cleanup() -> None:
        from botocore.exceptions import ClientError

        try:
            rds.delete_db_parameter_group(DBParameterGroupName=custom_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DBParameterGroupNotFound":
                raise

    ctx.on_cleanup(_safety_net_cleanup)

    rds.delete_db_parameter_group(DBParameterGroupName=custom_name)
    code2, message2 = _error_code(lambda: rds.describe_db_parameter_groups(DBParameterGroupName=custom_name))
    assert code2 == "DBParameterGroupNotFound", f"control group should be gone, got code={code2!r}"
    assert message2 == f"DBParameterGroup not found: {custom_name}", f"unexpected message: {message2!r}"


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
