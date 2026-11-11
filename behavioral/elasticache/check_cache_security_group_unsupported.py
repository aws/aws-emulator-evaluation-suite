"""cache-security-group-unsupported."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")

def _refusal(fn):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn)
    return _fault_base(code), message

CHECK = "cache-security-group-unsupported"
GROUP = 'overly-permissive'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCacheSecurityGroup and an unfiltered DescribeCacheSecurityGroups are refused with
    InvalidParameterValue "Use of cache security groups is not permitted in this API version for your
    account.", while DescribeCacheClusters succeeds, so the refusal is specific to EC2-Classic groups."""
    ec = ctx.client("elasticache")

    clusters = ec.describe_cache_clusters()
    assert isinstance(clusters.get("CacheClusters"), list), (
        f"expected DescribeCacheClusters to succeed as a positive control, got {clusters!r}"
    )

    name = ctx.unique_name("sim2real-behav-ecsecg-")
    refused = _refusal(
        lambda: ec.create_cache_security_group(
            CacheSecurityGroupName=name,
            Description="fidelity check security group",
        ),
    )
    assert refused == (
        "InvalidParameterValue",
        "Use of cache security groups is not permitted in this API version for your account.",
    ), f"expected InvalidParameterValue with its exact message, got {refused!r}"

    # The whole API surface is closed for this account/API version — even the
    # unfiltered list — so there is no way a group could have been created.
    refused = _refusal(lambda: ec.describe_cache_security_groups())
    assert refused == (
        "InvalidParameterValue",
        "Use of cache security groups is not permitted in this API version for your account.",
    ), f"expected InvalidParameterValue with its exact message, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
