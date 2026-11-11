"""ipam-policy-allocation-rule-private-pool-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipam-policy-allocation-rule-private-pool-rejected"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamPolicyAllocationRules rejects a ResourceType outside its closed enum (alb|eip|rds|rnat)
    and persists no rule, while the identical call with a valid ResourceType/pool pair succeeds; the
    enum is the documented boundary, a scope cross-check is not."""
    ec2 = ctx.client("ec2")

    ipam = _create_ipam_with_retry(ec2, ctx)
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: _delete_ipam_when_unblocked(ec2, ipam_id))
    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )
    public_scope_id = ipam["PublicDefaultScopeId"]

    public_pool_id = ec2.create_ipam_pool(
        IpamScopeId=public_scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        TagSpecifications=[
            {
                "ResourceType": "ipam-pool",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-pool-")}],
            }
        ],
    )["IpamPool"]["IpamPoolId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_pool(IpamPoolId=public_pool_id))
    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[public_pool_id])["IpamPools"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60,
    )

    policy_id = ec2.create_ipam_policy(
        IpamId=ipam_id,
        TagSpecifications=[
            {
                "ResourceType": "ipam-policy",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-policy-")}],
            }
        ],
    )["IpamPolicy"]["IpamPolicyId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id))
    _poll_until(
        lambda: ec2.describe_ipam_policies(IpamPolicyIds=[policy_id])["IpamPolicies"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60,
    )
    ec2.enable_ipam_policy(IpamPolicyId=policy_id)
    ctx.on_cleanup(lambda: ec2.disable_ipam_policy(IpamPolicyId=policy_id))

    docs_before = ec2.get_ipam_policy_allocation_rules(
        IpamPolicyId=policy_id, Locale=ctx.region, ResourceType="eip"
    )["IpamPolicyDocuments"]

    try:
        result = ec2.modify_ipam_policy_allocation_rules(
            IpamPolicyId=policy_id,
            Locale=ctx.region,
            ResourceType="not-a-real-resource-type",
            AllocationRules=[{"SourceIpamPoolId": public_pool_id}],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"expected an out-of-enum ResourceType to be rejected, but the call SUCCEEDED: {result!r}"
        )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "The resource type not-a-real-resource-type is not valid.", (
        f"unexpected InvalidParameterValue message {message!r}"
    )

    # Effect absent: the "eip" allocation-rule document is unchanged by the
    # rejected call.
    docs_after_reject = ec2.get_ipam_policy_allocation_rules(
        IpamPolicyId=policy_id, Locale=ctx.region, ResourceType="eip"
    )["IpamPolicyDocuments"]
    assert docs_after_reject == docs_before, (
        f"rejected call changed the eip allocation-rule document: "
        f"before={docs_before!r} after={docs_after_reject!r}"
    )

    # Positive control: a valid ResourceType/pool pair is accepted.
    ec2.modify_ipam_policy_allocation_rules(
        IpamPolicyId=policy_id,
        Locale=ctx.region,
        ResourceType="eip",
        AllocationRules=[{"SourceIpamPoolId": public_pool_id}],
    )
    docs_after = ec2.get_ipam_policy_allocation_rules(
        IpamPolicyId=policy_id, Locale=ctx.region, ResourceType="eip"
    )["IpamPolicyDocuments"]
    assert len(docs_after) == 1, f"expected exactly one eip allocation-rule document, got {docs_after!r}"
    assert [r["SourceIpamPoolId"] for r in docs_after[0]["AllocationRules"]] == [public_pool_id], (
        f"expected the eip allocation rule to point at {public_pool_id!r}, got {docs_after[0]!r}"
    )


# ===== IPAM helpers =====
def _create_ipam_with_retry(ec2, ctx):
    """Create an IPAM, backing off on ResourceLimitExceeded: the per-account IPAM quota is small
    and shared with concurrently running checks, so it frees up as their teardowns finish."""
    budget = 300.0
    left = ctx.time_left()
    if left is not None:
        budget = min(budget, left)
    deadline = time.monotonic() + budget
    while True:
        try:
            name = ctx.unique_name("sim2real-ipam-")
            return ec2.create_ipam(
                Description=name,
                OperatingRegions=[{"RegionName": ctx.region}],
                TagSpecifications=[
                    {"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}
                ],
            )["Ipam"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceLimitExceeded" \
                    or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_ipam_when_unblocked(ec2, ipam_id, timeout_s=300.0):
    """Teardown: cascade-delete the IPAM, retrying while a pool deleted just before it still
    holds the public scope (DependencyViolation), and tolerating an already-gone IPAM."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidIpamId.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
