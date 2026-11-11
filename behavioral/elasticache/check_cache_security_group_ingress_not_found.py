"""cache-security-group-ingress-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _client_error(fn):
    """Call fn(); return the botocore ClientError raised, or None if it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None

def _assert_closed(fn, expected_code):
    """Assert fn() is refused with `expected_code` and the account-wide closure message
    real AWS gives for the whole CacheSecurityGroup surface on a VPC-only account —
    never a per-name CacheSecurityGroupNotFoundFault."""
    exc = _client_error(fn)
    assert exc is not None, f"expected {expected_code} but the call SUCCEEDED"
    error = exc.response.get("Error", {})
    code = error.get("Code")
    assert _fault_base(code) == _fault_base(expected_code), f"expected {expected_code}, got {code}"
    message = error.get("Message", "")
    assert "not permitted" in message.lower(), (
        f"expected the account-wide 'not permitted' closure message, got {message!r}"
    )
    return code

CHECK = "cache-security-group-ingress-not-found"
GROUP = 'security-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a VPC-only account the whole CacheSecurityGroup API is closed: Describe, Authorize/RevokeIngress and
    Delete on a missing group are refused with InvalidParameterValue, not CacheSecurityGroupNotFound, while
    DescribeCacheClusters succeeds."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-ecsecg-missing-")
    owner_id = "123456789012"
    ec2_group_name = ctx.unique_name("sim2real-behav-ec2sg-")

    # Positive control: elasticache itself is reachable for this account/credentials --
    # only the EC2-Classic cache-security-group surface is closed, not the whole API.
    control = ec.describe_cache_clusters()
    assert isinstance(control["CacheClusters"], list), (
        "describe_cache_clusters positive control did not return a CacheClusters list"
    )

    _assert_closed(
        lambda: ec.describe_cache_security_groups(CacheSecurityGroupName=name),
        "InvalidParameterValueException",
    )
    _assert_closed(
        lambda: ec.authorize_cache_security_group_ingress(
            CacheSecurityGroupName=name,
            EC2SecurityGroupName=ec2_group_name,
            EC2SecurityGroupOwnerId=owner_id,
        ),
        "InvalidParameterValueException",
    )
    _assert_closed(
        lambda: ec.revoke_cache_security_group_ingress(
            CacheSecurityGroupName=name,
            EC2SecurityGroupName=ec2_group_name,
            EC2SecurityGroupOwnerId=owner_id,
        ),
        "InvalidParameterValueException",
    )
    _assert_closed(
        lambda: ec.delete_cache_security_group(CacheSecurityGroupName=name),
        "InvalidParameterValueException",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
