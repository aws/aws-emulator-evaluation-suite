"""describe-security-groups."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-security-groups"
GROUP = 'security_groups'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBSecurityGroups without a filter returns a list, and an unknown DBSecurityGroupName is
    rejected with DBSecurityGroupNotFound rather than answering empty."""
    rds = ctx.client("rds")
    resp = rds.describe_db_security_groups()
    assert isinstance(resp.get("DBSecurityGroups"), list)

    bogus_name = ctx.unique_name("sim2real-behav-sg-missing-")
    err = _rejection(lambda: rds.describe_db_security_groups(DBSecurityGroupName=bogus_name))
    assert err.get("Code") == "DBSecurityGroupNotFound", (
        f"expected DBSecurityGroupNotFound, got {err}"
    )
    assert err.get("Message") == f"DBSecurityGroup {bogus_name} not found.", (
        f"unexpected DBSecurityGroupNotFound message: {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
