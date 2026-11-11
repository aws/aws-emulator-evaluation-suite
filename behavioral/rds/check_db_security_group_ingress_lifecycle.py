"""db-security-group-ingress-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "db-security-group-ingress-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]

_TEST_CIDR = "203.0.113.0/24"
_VPC_REFUSAL = (
    "VPC DB Security Groups cannot be modified with this API version.  Please use an API "
    "version between 2012-01-15 and 2012-10-31 to modify this group."
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBSecurityGroup on a VPC-only account yields a VPC-platform group that describes and
    deletes, but Authorize/RevokeDBSecurityGroupIngress refuse it with InvalidParameterValue.
    """
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-dbsg-")

    rds.create_db_security_group(
        DBSecurityGroupName=name,
        DBSecurityGroupDescription="sim2real behavioral check",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete(rds, name))

    described = rds.describe_db_security_groups(DBSecurityGroupName=name)["DBSecurityGroups"][0]
    assert described["DBSecurityGroupName"] == name
    assert described["IPRanges"] == []

    # DB security group ingress applies only to EC2-Classic; no account created after 2013 has it,
    # so the authorize/revoke lifecycle cannot succeed and the refusal is what is asserted.
    code, message = _error_code_and_message(
        lambda: rds.authorize_db_security_group_ingress(DBSecurityGroupName=name, CIDRIP=_TEST_CIDR)
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue authorizing ingress on a VPC-platform DB security "
        f"group, got {code!r}: {message!r}"
    )
    assert message == _VPC_REFUSAL, (
        f"expected the VPC-platform refusal message, got {code!r}: {message!r}"
    )

    # Effect absent: the refused authorize left no ingress rule behind.
    described = rds.describe_db_security_groups(DBSecurityGroupName=name)["DBSecurityGroups"][0]
    assert described["IPRanges"] == []

    # Revoke on the same VPC-platform group is refused for the same reason — not
    # AuthorizationNotFoundFault, which would (wrongly) suggest the group type itself was fine
    # and only the specific rule was missing.
    code, message = _error_code_and_message(
        lambda: rds.revoke_db_security_group_ingress(DBSecurityGroupName=name, CIDRIP=_TEST_CIDR)
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue revoking ingress on a VPC-platform DB security "
        f"group, got {code!r}: {message!r}"
    )
    assert message == _VPC_REFUSAL, (
        f"expected the VPC-platform refusal message, got {code!r}: {message!r}"
    )

    rds.delete_db_security_group(DBSecurityGroupName=name)
    code, message = _error_code_and_message(lambda: rds.describe_db_security_groups(DBSecurityGroupName=name))
    assert code == "DBSecurityGroupNotFound", f"expected DBSecurityGroupNotFound, got {code!r}: {message!r}"
    assert message == f"DBSecurityGroup {name} not found.", (
        f"expected the not-found message naming {name!r}, got {message!r}"
    )



def _safe_delete(rds, name: str) -> None:
    try:
        rds.delete_db_security_group(DBSecurityGroupName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBSecurityGroupNotFound":
            raise


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
