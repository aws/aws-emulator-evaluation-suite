"""security-group-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-lifecycle"
GROUP = 'security_groups'
SERVICES = ['rds']

ERR_DB_SECURITY_GROUP_NOT_FOUND = "DBSecurityGroupNotFound"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB security group is describable after create and DBSecurityGroupNotFound after delete;
    deleting it again is rejected with DBSecurityGroupNotFound, and the freed name is reusable.
    DB security groups are EC2-Classic; on VPC-only accounts creation itself can be rejected."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-secg-")
    rds.create_db_security_group(
        DBSecurityGroupName=name, DBSecurityGroupDescription="behavioral check"
    )
    ctx.on_cleanup(lambda: rds.delete_db_security_group(DBSecurityGroupName=name))

    resp = rds.describe_db_security_groups(DBSecurityGroupName=name)
    described = resp["DBSecurityGroups"][0]
    assert described["DBSecurityGroupName"] == name, (
        f"expected DBSecurityGroupName {name!r}, got {described!r}"
    )

    rds.delete_db_security_group(DBSecurityGroupName=name)
    code, message = _error(
        lambda: rds.describe_db_security_groups(DBSecurityGroupName=name)
    )
    assert code == ERR_DB_SECURITY_GROUP_NOT_FOUND, f"unexpected error code: {code}"
    expected = f"DBSecurityGroup {name} not found."
    assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    code2, message2 = _error(
        lambda: rds.delete_db_security_group(DBSecurityGroupName=name)
    )
    assert code2 == ERR_DB_SECURITY_GROUP_NOT_FOUND, f"unexpected error code: {code2}"
    expected2 = f"DBSecurityGroup not found: {name}"
    assert message2 == expected2, f"unexpected error message: {message2!r} != {expected2!r}"

    # The freed name is reusable: recreate under the same identifier.
    rds.create_db_security_group(
        DBSecurityGroupName=name, DBSecurityGroupDescription="behavioral check (reused)"
    )
    resp2 = rds.describe_db_security_groups(DBSecurityGroupName=name)
    described2 = resp2["DBSecurityGroups"][0]
    assert described2["DBSecurityGroupName"] == name, (
        f"expected reused DBSecurityGroupName {name!r}, got {described2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
