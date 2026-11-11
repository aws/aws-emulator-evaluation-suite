"""op-contract-get-ipam-policy-allocation-rules."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-policy-allocation-rules"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamPolicyAllocationRules returns no allocation-rule documents for a new IPAM policy with no
    rule configured; DryRun fails with DryRunOperation and the standard message."""
    ec2 = ctx.client("ec2")
    policy_id = _create_ipam_policy(ctx, ec2)

    rules = ec2.get_ipam_policy_allocation_rules(IpamPolicyId=policy_id)["IpamPolicyDocuments"]
    assert rules == [], (
        f"expected no allocation-rule documents for a policy with no rules ever "
        f"configured, got {rules!r}"
    )

    code, message = _client_error(
        lambda: ec2.get_ipam_policy_allocation_rules(IpamPolicyId=policy_id, DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"


# ===== helpers =====


def _create_ipam_policy(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = _create_ipam_with_retry(
        ctx,
        ec2,
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    policy = ec2.create_ipam_policy(
        IpamId=ipam_id,
        ClientToken=ctx.unique_name("sim2real-behav-policy-"),
        TagSpecifications=[
            {"ResourceType": "ipam-policy", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["IpamPolicy"]
    policy_id = policy["IpamPolicyId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id))
    return policy_id


def _create_ipam_with_retry(ctx, ec2, **kwargs):
    """The per-account IPAM quota is shared with concurrently running checks, and deleting their
    IPAMs is unsafe: retry ResourceLimitExceeded every 2 s for up to 60 s while their teardowns free it."""
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            return ec2.create_ipam(**kwargs)["Ipam"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"account IPAM quota still exhausted after retrying up to 60 s: {err}") from err
        time.sleep(2)


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

