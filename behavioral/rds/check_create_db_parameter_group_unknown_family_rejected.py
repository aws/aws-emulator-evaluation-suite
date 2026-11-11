"""create-db-parameter-group-unknown-family-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-db-parameter-group-unknown-family-rejected"
GROUP = "parameter_groups"
SERVICES = ["rds"]

_UNKNOWN_FAMILY = "postgres99"
#: CreateDBParameterGroup naming a family RDS does not have; {family} is that family.
_UNKNOWN_FAMILY_REFUSED = (
    "InvalidParameterValue",
    "ParameterGroupFamily {family} is not a valid parameter group family",
)
#: DescribeDBParameterGroups for a name no group has; {name} is that name.
_GROUP_NOT_FOUND = ("DBParameterGroupNotFound", "DBParameterGroup not found: {name}")
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _error_detail(fn):
    """The AWS error (code, message) raised by fn(); raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"the call that must be refused succeeded instead: {result!r}")


def _delete_group(rds, name):
    """Delete a parameter group; not-found means already gone."""
    try:
        rds.delete_db_parameter_group(DBParameterGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBParameterGroupNotFound":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBParameterGroup with family postgres99 is refused and creates no group.

    The refusal is InvalidParameterValue; the same name with the default postgres family is then
    created.
    """
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-")
    ctx.on_cleanup(lambda: _delete_group(rds, name))

    got = _error_detail(
        lambda: rds.create_db_parameter_group(
            DBParameterGroupName=name,
            DBParameterGroupFamily=_UNKNOWN_FAMILY,
            Description="sim2real unknown family",
            Tags=_MANAGED_TAGS,
        )
    )
    want = (_UNKNOWN_FAMILY_REFUSED[0], _UNKNOWN_FAMILY_REFUSED[1].format(family=_UNKNOWN_FAMILY))
    assert got == want, (
        f"CreateDBParameterGroup family {_UNKNOWN_FAMILY!r}: expected {want!r}, got {got!r}"
    )

    absent = _error_detail(lambda: rds.describe_db_parameter_groups(DBParameterGroupName=name))
    want_absent = (_GROUP_NOT_FOUND[0], _GROUP_NOT_FOUND[1].format(name=name))
    assert absent == want_absent, (
        f"the refused create must leave no group; DescribeDBParameterGroups gave {absent!r}, "
        f"expected {want_absent!r}"
    )

    family = rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True)[
        "DBEngineVersions"
    ][0]["DBParameterGroupFamily"]
    created = rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily=family,
        Description="sim2real default family",
        Tags=_MANAGED_TAGS,
    )["DBParameterGroup"]
    assert (created["DBParameterGroupName"], created["DBParameterGroupFamily"]) == (name, family), (
        f"the same name with family {family!r} must be created; got {created!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
