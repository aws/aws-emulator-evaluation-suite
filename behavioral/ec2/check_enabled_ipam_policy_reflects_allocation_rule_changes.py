"""enabled-ipam-policy-reflects-allocation-rule-changes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enabled-ipam-policy-reflects-allocation-rule-changes"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetEnabledIpamPolicy names the policy most recently enabled for the account, and
    GetIpamPolicyAllocationRules returns exactly the rules of the latest
    ModifyIpamPolicyAllocationRules call, both for the first rule and for a change to another pool."""
    ec2 = ctx.client("ec2")

    ipam = _create_ipam_with_retry(ec2, ctx)
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: _delete_ipam(ec2, ipam_id))
    _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60,
    )
    public_scope_id = ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]["PublicDefaultScopeId"]

    pool_name = ctx.unique_name("sim2real-ipam-pool-")
    pool = ec2.create_ipam_pool(
        IpamScopeId=public_scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        TagSpecifications=[
            {"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": pool_name}]}
        ],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id))
    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60,
    )

    pool2_name = ctx.unique_name("sim2real-ipam-pool-")
    pool2_id = ec2.create_ipam_pool(
        IpamScopeId=public_scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        TagSpecifications=[
            {"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": pool2_name}]}
        ],
    )["IpamPool"]["IpamPoolId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_pool(IpamPoolId=pool2_id))
    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool2_id])["IpamPools"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60,
    )

    policy_name = ctx.unique_name("sim2real-ipam-policy-")
    policy = ec2.create_ipam_policy(
        IpamId=ipam_id,
        TagSpecifications=[
            {"ResourceType": "ipam-policy", "Tags": [{"Key": "Name", "Value": policy_name}]}
        ],
    )["IpamPolicy"]
    policy_id = policy["IpamPolicyId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id))
    _poll_until(
        lambda: ec2.describe_ipam_policies(IpamPolicyIds=[policy_id])["IpamPolicies"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60,
    )

    ec2.enable_ipam_policy(IpamPolicyId=policy_id)
    ctx.on_cleanup(lambda: ec2.disable_ipam_policy(IpamPolicyId=policy_id))

    # Enablement can take a while to propagate to GetEnabledIpamPolicy, and
    # occasionally needs to be re-asserted if a differently-enabled policy
    # was still winning the race.
    enabled = None
    left = ctx.time_left()
    deadline = time.monotonic() + (120 if left is None else max(1.0, min(120, left - 5)))
    attempt = 0
    while time.monotonic() < deadline:
        candidate = ec2.get_enabled_ipam_policy()
        id_keys = [k for k in candidate if "policyid" in k.lower()]
        if id_keys and candidate[id_keys[0]] == policy_id:
            enabled = candidate
            break
        attempt += 1
        if attempt % 15 == 0:
            # Re-assert enablement (every ~30 s) in case a stale/other policy is winning.
            ec2.enable_ipam_policy(IpamPolicyId=policy_id)
        time.sleep(2)

    assert enabled is not None, (
        f"GetEnabledIpamPolicy never converged on the policy we enabled "
        f"({policy_id!r}) within 120s; last response: "
        f"{ec2.get_enabled_ipam_policy()!r}"
    )
    id_keys = [k for k in enabled if "policyid" in k.lower()]
    assert enabled[id_keys[0]] == policy_id
    enabled_keys = [k for k in enabled if k.lower().endswith("enabled")]
    assert enabled_keys, f"no enabled-flag field found in GetEnabledIpamPolicy response: {enabled!r}"
    assert enabled[enabled_keys[0]] is True
    managed_by_keys = [k for k in enabled if "managedby" in k.lower()]
    if managed_by_keys:
        assert enabled[managed_by_keys[0]] == "account"

    # Set an allocation rule mapping the "eip" resource type to our pool.
    ec2.modify_ipam_policy_allocation_rules(
        IpamPolicyId=policy_id,
        Locale=ctx.region,
        ResourceType="eip",
        AllocationRules=[{"SourceIpamPoolId": pool_id}],
    )
    docs = ec2.get_ipam_policy_allocation_rules(
        IpamPolicyId=policy_id, Locale=ctx.region, ResourceType="eip"
    )["IpamPolicyDocuments"]
    assert len(docs) == 1
    assert docs[0]["ResourceType"] == "eip"
    assert [r["SourceIpamPoolId"] for r in docs[0]["AllocationRules"]] == [pool_id]

    # Change the rule to point at a different pool -- this should be
    # reflected on a subsequent read (allow for brief eventual-consistency
    # lag, same as the initial-set path above).
    ec2.modify_ipam_policy_allocation_rules(
        IpamPolicyId=policy_id,
        Locale=ctx.region,
        ResourceType="eip",
        AllocationRules=[{"SourceIpamPoolId": pool2_id}],
    )
    docs_after = _poll_until(
        lambda: ec2.get_ipam_policy_allocation_rules(
            IpamPolicyId=policy_id, Locale=ctx.region, ResourceType="eip"
        )["IpamPolicyDocuments"],
        lambda docs: len(docs) == 1
        and [r["SourceIpamPoolId"] for r in docs[0]["AllocationRules"]] == [pool2_id],
        timeout_s=60,
    )
    assert len(docs_after) == 1
    assert [r["SourceIpamPoolId"] for r in docs_after[0]["AllocationRules"]] == [pool2_id]


# ===== helpers (self-contained) =====
def _create_ipam_with_retry(ec2, ctx):
    """The per-account Ipam quota is small and shared across every behavioral
    check that creates one, including checks running concurrently in other
    processes. Deleting other sim2real-* Ipams on ResourceLimitExceeded is
    unsafe -- it can rip out an Ipam a concurrently running check just
    created and is still using (observed as a subsequent IncorrectState
    "delete-in-progress" error on that check). Instead, just back off and
    retry: the quota frees up on its own as other checks finish and run
    their own teardown."""
    name = ctx.unique_name("sim2real-ipam-")
    deadline = time.monotonic() + 300
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ec2.create_ipam(
                Description=name,
                OperatingRegions=[{"RegionName": ctx.region}],
                TagSpecifications=[
                    {"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}
                ],
            )["Ipam"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            last_exc = exc
            time.sleep(2)

    raise last_exc


def _delete_ipam(ec2, ipam_id, timeout_s=300.0):
    """Delete the IPAM, retrying DependencyViolation every 2 s while its just-deleted pools are
    still detaching from the scope; not-found counts as gone, anything else raises."""
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
