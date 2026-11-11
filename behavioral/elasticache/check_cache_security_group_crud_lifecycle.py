"""cache-security-group-crud-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cache-security-group-crud-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Cache security groups belong to EC2-Classic, which a VPC-only account lacks: Create, Describe and
    Delete on one group name are each rejected with InvalidParameterValue "Use of cache security groups is not
    permitted in this API version for your account.", while DescribeCacheClusters succeeds."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-csg-")
    description = "sim2real cache security group lifecycle check"

    # Positive control: the account/credentials are otherwise healthy for elasticache.
    ec.describe_cache_clusters()

    create_code, create_message = _error(
        lambda: ec.create_cache_security_group(CacheSecurityGroupName=name, Description=description)
    )
    assert create_code == "InvalidParameterValue", (
        f"expected CreateCacheSecurityGroup to be rejected with InvalidParameterValue, got {create_code!r}"
    )
    assert create_message == "Use of cache security groups is not permitted in this API version for your account.", (
        f"unexpected InvalidParameterValue message: {create_message!r}"
    )

    # Effect absent: no group exists under this name, so a named describe is
    # rejected the same way -- never a silent empty list.
    describe_code, describe_message = _error(lambda: ec.describe_cache_security_groups(CacheSecurityGroupName=name))
    assert describe_code == "InvalidParameterValue", f"expected InvalidParameterValue, got {describe_code!r}"
    assert describe_message == "Use of cache security groups is not permitted in this API version for your account.", (
        f"unexpected InvalidParameterValue message: {describe_message!r}"
    )

    # Delete on a name that was never (and could never be) created is rejected
    # identically, not treated as an idempotent no-op.
    delete_code, delete_message = _error(lambda: ec.delete_cache_security_group(CacheSecurityGroupName=name))
    assert delete_code == "InvalidParameterValue", f"expected InvalidParameterValue, got {delete_code!r}"
    assert delete_message == "Use of cache security groups is not permitted in this API version for your account.", (
        f"unexpected InvalidParameterValue message: {delete_message!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError("expected the call to be rejected, but it SUCCEEDED")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
