"""create-db-parameter-group-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-db-parameter-group-duplicate-name-rejected"
GROUP = "deploy"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBParameterGroup with an existing name is rejected with DBParameterGroupAlreadyExistsFault
    and leaves the original's description unchanged; a distinct name succeeds, and the original name
    is creatable again once that group is deleted."""
    rds = ctx.client("rds")
    versions = rds.describe_db_engine_versions(Engine="mysql", DefaultOnly=True)["DBEngineVersions"]
    if not versions:
        raise AssertionError("no default mysql engine version available to source a parameter group family")
    family = versions[0]["DBParameterGroupFamily"]

    name = ctx.unique_name("sim2real-rds-pg-dup-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily=family,
        Description="sim2real original",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=name))

    code, message = _error_code(lambda: rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily=family,
        Description="sim2real duplicate attempt",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    ))
    assert code == "DBParameterGroupAlreadyExists", f"expected DBParameterGroupAlreadyExists, got {code!r}"
    expected = f"Parameter group {name} already exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    group = rds.describe_db_parameter_groups(DBParameterGroupName=name)["DBParameterGroups"][0]
    assert group["Description"] == "sim2real original", (
        f"expected description 'sim2real original' unchanged by the rejected duplicate, "
        f"got {group['Description']!r}"
    )

    other_name = ctx.unique_name("sim2real-rds-pg-ok-")
    rds.create_db_parameter_group(
        DBParameterGroupName=other_name,
        DBParameterGroupFamily=family,
        Description="sim2real control",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_parameter_group(DBParameterGroupName=other_name))
    other = rds.describe_db_parameter_groups(DBParameterGroupName=other_name)["DBParameterGroups"][0]
    assert other["DBParameterGroupName"].lower() == other_name.lower(), (
        f"expected DBParameterGroupName {other_name!r}, got {other['DBParameterGroupName']!r}"
    )
    assert other["Description"] == "sim2real control", (
        f"expected description 'sim2real control', got {other['Description']!r}"
    )

    rds.delete_db_parameter_group(DBParameterGroupName=name)
    _wait_for_absence(rds, name)
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily=family,
        Description="sim2real restored",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    restored = rds.describe_db_parameter_groups(DBParameterGroupName=name)["DBParameterGroups"][0]
    assert restored["Description"] == "sim2real restored", (
        f"expected the freed name {name!r} to be creatable again with a fresh description, "
        f"got {restored['Description']!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target that accepts input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected DBParameterGroupAlreadyExists, but the duplicate create SUCCEEDED and returned {result!r}")


def _wait_for_absence(rds, name, deadline_s=60, interval_s=3):
    """Bounded retry: DeleteDBParameterGroup can lag before the name is free again."""
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_parameter_groups(DBParameterGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBParameterGroupNotFound":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"{name} still present {deadline_s}s after DeleteDBParameterGroup")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
