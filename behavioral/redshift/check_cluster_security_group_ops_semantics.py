"""cluster-security-group-ops-semantics."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)

_DISCONTINUED_MSG = (
    "Amazon Redshift has discontinued cluster security groups. For security group "
    "configuration, associate VPC security groups when creating or modifying your cluster."
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _call(fn):
    """Call *fn*; return (code, message). code is "OK" on success and message carries the AWS error
    text for a tight contract check."""
    try:
        result = _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return f"EXC:{type(exc).__name__}", str(exc)
    return "OK", repr(result)


def _probe(cases):
    """{label: callable} -> {label: (code, message)}; never raises."""
    return {label: _call(fn) for label, fn in cases.items()}


CHECK = "cluster-security-group-ops-semantics"
GROUP = 'security-group'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Cluster security groups are discontinued: create, describe (even unfiltered), authorize/revoke
    ingress and delete are all rejected with InvalidParameterValue rather than served.
    """
    rs = ctx.client("redshift")

    # Positive control: prove the account and credentials are otherwise healthy for redshift, so
    # the rejections below cannot be explained by a broken client instead of the discontinuation.
    health = rs.describe_clusters()
    assert "Clusters" in health, f"DescribeClusters must succeed as a health check, got {health}"

    create_code, create_msg = _call(lambda: rs.create_cluster_security_group(
        ClusterSecurityGroupName=ctx.unique_name("sim2real-behav-rs-csg-"),
        Description="behavioral fidelity discontinued-feature check",
    ))
    assert create_code == "InvalidParameterValue", (
        f"CreateClusterSecurityGroup is discontinued and must be rejected, "
        f"got {create_code}: {create_msg!r}"
    )
    assert create_msg == _DISCONTINUED_MSG, (
        f"CreateClusterSecurityGroup must reject with the discontinuation message, "
        f"got {create_code}: {create_msg!r}"
    )

    missing = ctx.unique_name("sim2real-behav-rs-csg-missing-")
    cases = {
        # No filter at all: the whole read surface is gone, not merely a lookup-by-name.
        "DescribeClusterSecurityGroups(no filter)": lambda: rs.describe_cluster_security_groups(),
        "DescribeClusterSecurityGroups": lambda: rs.describe_cluster_security_groups(
            ClusterSecurityGroupName=missing
        ),
        "AuthorizeClusterSecurityGroupIngress": lambda: rs.authorize_cluster_security_group_ingress(
            ClusterSecurityGroupName=missing, CIDRIP="10.0.0.0/24"
        ),
        "RevokeClusterSecurityGroupIngress": lambda: rs.revoke_cluster_security_group_ingress(
            ClusterSecurityGroupName=missing, CIDRIP="10.0.0.0/24"
        ),
        "DeleteClusterSecurityGroup": lambda: rs.delete_cluster_security_group(
            ClusterSecurityGroupName=missing
        ),
    }
    observed = _probe(cases)
    for label, (code, msg) in observed.items():
        assert code == "InvalidParameterValue", (
            f"{label}: security-group contract drift, expected InvalidParameterValue, "
            f"got {code}: {msg!r}"
        )
        assert msg == _DISCONTINUED_MSG, (
            f"{label}: expected the discontinuation message (not a generic "
            f"InvalidParameterValue), got {msg!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
