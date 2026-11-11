"""authorize-security-group-ingress."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorize-security-group-ingress"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_SECURITY_GROUP_NOT_FOUND = "DBSecurityGroupNotFound"


def _error_detail(fn, what):
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"{what} succeeded; expected a rejection")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AuthorizeDBSecurityGroupIngress and DescribeDBSecurityGroups on an unknown name fail with
    DBSecurityGroupNotFound, while the same call on a group the check created does not."""
    rds = ctx.client("rds")

    real_group = ctx.unique_name("sim2real-behav-secg-real-")
    rds.create_db_security_group(
        DBSecurityGroupName=real_group, DBSecurityGroupDescription="sim2real positive control"
    )
    ctx.on_cleanup(lambda: rds.delete_db_security_group(DBSecurityGroupName=real_group))
    described = rds.describe_db_security_groups(DBSecurityGroupName=real_group)["DBSecurityGroups"]
    assert len(described) == 1 and described[0]["DBSecurityGroupName"] == real_group, (
        f"positive control group not independently readable: {described!r}"
    )
    # The control may succeed or be refused for an unrelated reason; it only must not
    # come back not-found.
    try:
        rds.authorize_db_security_group_ingress(DBSecurityGroupName=real_group, CIDRIP="10.0.0.0/32")
        real_code = None
    except ClientError as exc:
        real_code = exc.response.get("Error", {}).get("Code")
    assert real_code != ERR_DB_SECURITY_GROUP_NOT_FOUND, (
        f"a DB security group this check just created and confirmed exists was "
        f"reported not-found: {real_code!r}"
    )

    bogus_group = ctx.unique_name("sim2real-behav-secg-missing-")
    code, message = _error_detail(
        lambda: rds.authorize_db_security_group_ingress(
            DBSecurityGroupName=bogus_group, CIDRIP="10.0.0.0/32"
        ),
        "AuthorizeDBSecurityGroupIngress on an unknown group",
    )
    assert code == ERR_DB_SECURITY_GROUP_NOT_FOUND, f"unexpected error code: {code!r}"
    expected = f"DBSecurityGroup not found: {bogus_group}"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Independent terminal read: the bogus name never came into existence either.
    describe_code, describe_message = _error_detail(
        lambda: rds.describe_db_security_groups(DBSecurityGroupName=bogus_group),
        "DescribeDBSecurityGroups on an unknown group",
    )
    assert describe_code == ERR_DB_SECURITY_GROUP_NOT_FOUND, (
        f"unexpected error code describing bogus group: {describe_code!r}"
    )
    describe_expected = f"DBSecurityGroup {bogus_group} not found."
    assert describe_message == describe_expected, (
        f"unexpected describe message: {describe_message!r} (expected {describe_expected!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
