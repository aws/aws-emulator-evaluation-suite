"""security-group-ingress-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "security-group-ingress-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBSecurityGroup creates a group with no ingress, AuthorizeDBSecurityGroupIngress on it is
    rejected with InvalidParameterValue and leaves it unchanged, and after delete both a describe and
    a second delete are rejected with DBSecurityGroupNotFound."""

    rds = ctx.client("rds")
    group_name = ctx.unique_name("sim2real-dbsg-")

    rds.create_db_security_group(
        DBSecurityGroupName=group_name,
        DBSecurityGroupDescription="sim2real behavioral ingress lifecycle",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete(rds, group_name))

    described = rds.describe_db_security_groups(DBSecurityGroupName=group_name)["DBSecurityGroups"][0]
    assert described["DBSecurityGroupName"] == group_name, (
        f"expected DBSecurityGroupName {group_name!r}, got {described['DBSecurityGroupName']!r}"
    )
    assert described.get("IPRanges", []) == [], (
        f"a freshly created DB security group must have no IPRanges, got {described.get('IPRanges')!r}"
    )

    test_cidr = "203.0.113.0/32"
    try:
        rds.authorize_db_security_group_ingress(DBSecurityGroupName=group_name, CIDRIP=test_cidr)
        raise AssertionError(
            "AuthorizeDBSecurityGroupIngress unexpectedly succeeded against a VPC-platform "
            "DB security group; the EC2-Classic-era ingress API must refuse it"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        assert code == "InvalidParameterValue", (
            f"expected InvalidParameterValue for ingress on a VPC-platform DB security "
            f"group, got {code}: {message}"
        )
        expected = (
            "VPC DB Security Groups cannot be modified with this API version.  "
            "Please use an API version between 2012-01-15 and 2012-10-31 to modify this group."
        )
        assert message == expected, (
            f"expected the VPC-platform refusal message {expected!r}, got {code}: {message!r}"
        )

    # Effect absent: the refused authorization left no ingress rule behind.
    after = rds.describe_db_security_groups(DBSecurityGroupName=group_name)["DBSecurityGroups"][0]
    assert after.get("IPRanges", []) == [], (
        f"a refused authorization must not add an IPRange, got {after.get('IPRanges')!r}"
    )
    assert after.get("EC2SecurityGroups", []) == [], (
        f"a refused authorization must not add an EC2SecurityGroup, got {after.get('EC2SecurityGroups')!r}"
    )

    rds.delete_db_security_group(DBSecurityGroupName=group_name)
    try:
        rds.describe_db_security_groups(DBSecurityGroupName=group_name)
        raise AssertionError("security group still describable after delete")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "DBSecurityGroupNotFound", f"expected DBSecurityGroupNotFound, got {code}"
        message = e.response["Error"]["Message"]
        expected = f"DBSecurityGroup {group_name} not found."
        assert message == expected, f"unexpected error message: {message!r} != {expected!r}"

    # Deletes prove gone AND unusable: a second delete on the now-dead id must also fail,
    # not silently no-op, and must not resurrect the group.
    try:
        rds.delete_db_security_group(DBSecurityGroupName=group_name)
        raise AssertionError("a second delete of an already-deleted security group unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "DBSecurityGroupNotFound", f"expected DBSecurityGroupNotFound on double delete, got {code}"
        message = e.response["Error"]["Message"]
        expected = f"DBSecurityGroup not found: {group_name}"
        assert message == expected, f"unexpected error message on double delete: {message!r} != {expected!r}"


def _safe_delete(rds, group_name):
    try:
        rds.delete_db_security_group(DBSecurityGroupName=group_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBSecurityGroupNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
