"""op-contract-modify-ipam-policy-allocation-rules."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-ipam-policy-allocation-rules"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamPolicyAllocationRules maps a resource type to a real IPAM pool and clears that
    mapping again, each transition confirmed by an independent GetIpamPolicyAllocationRules read
    rather than the mutating call's own echo, and rejects a resource type outside its alb|eip|rds|rnat enum."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_ipam_policy") or not hasattr(ec2, "modify_ipam_policy_allocation_rules"):
        raise AssertionError("botocore in this environment lacks the IPAM policy APIs")

    ipam_id, _private_scope_id, public_scope_id = _create_ipam(ctx, ec2)

    try:
        ec2.modify_ipam(IpamId=ipam_id, Tier="advanced")
    except Exception:
        pass  # IPAM policies may already be usable without an explicit tier toggle

    # The tier upgrade (free -> advanced) that unlocks IPAM policy allocation
    # rules is asynchronous: the Ipam briefly reports State="modify-in-progress"
    # after ModifyIpam returns. If a policy's allocation rules are created
    # before the upgrade finishes propagating, ModifyIpamPolicyAllocationRules
    # can spuriously report InvalidIpamPolicyAllocationRules.NotFound even for
    # a freshly-set rule. Poll until the tier change has settled.
    ipam_state = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i.get("Tier") == "advanced" and i.get("State") != "modify-in-progress",
        timeout_s=120,
        interval_s=5,
    )
    if not ipam_state or ipam_state.get("Tier") != "advanced":
        raise AssertionError(
            f"IPAM never reached advanced tier (last: {ipam_state}); allocation rules require advanced tier",
        )

    policy_name = ctx.unique_name("sim2real-behav-ipam-policy-")
    try:
        policy = ec2.create_ipam_policy(
            IpamId=ipam_id,
            TagSpecifications=[{"ResourceType": "ipam-policy", "Tags": [{"Key": "Name", "Value": policy_name}]}],
        )["IpamPolicy"]
    except Exception as exc:  # pragma: no cover - environment-dependent premium feature
        raise AssertionError(f"IPAM policy feature unavailable in this account/region: {exc}")
    policy_id = policy["IpamPolicyId"]

    def _cleanup_policy():
        _delete_with_retry(
            lambda: ec2.delete_ipam_policy(IpamPolicyId=policy_id), not_found="InvalidIpamPolicyId.NotFound"
        )

    ctx.on_cleanup(_cleanup_policy)

    pool_id = _create_ipam_pool(ctx, ec2, public_scope_id)

    # ModifyIpamPolicyAllocationRules rejects clearing (AllocationRules=[]) a
    # (policy, locale, resource-type) tuple that has never had a rule set
    # (InvalidIpamPolicyAllocationRules.NotFound). Establish a real rule first
    # (mapping "eip" to the pool just created) so that the subsequent "clear"
    # call is operating on an existing rule set.
    #
    # A freshly created IPAM policy does not immediately expose every
    # (locale, resource-type) combination as modifiable: the very first
    # ModifyIpamPolicyAllocationRules call for a given tuple can itself
    # spuriously report InvalidIpamPolicyAllocationRules.NotFound for a
    # short window after CreateIpamPolicy returns, before that tuple has
    # propagated. Poll (retrying only on that specific error code) until
    # the initial rule can be established.
    from botocore.exceptions import ClientError

    def _try_establish():
        try:
            return ec2.modify_ipam_policy_allocation_rules(
                IpamPolicyId=policy_id,
                Locale=ctx.region,
                ResourceType="eip",
                AllocationRules=[{"SourceIpamPoolId": pool_id}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidIpamPolicyAllocationRules.NotFound":
                return None
            raise

    establish_resp = _poll_until(_try_establish, lambda r: r is not None, timeout_s=90, interval_s=5)
    if establish_resp is None:
        raise AssertionError(
            "freshly-created IPAM policy never became modifiable for the eip resource type "
            "within the timeout",
        )

    # Independent terminal read: ModifyIpamPolicyAllocationRules reporting success is not proof the
    # rule actually landed. GetIpamPolicyAllocationRules is a separate read operation at the same
    # destination; use it, not the mutating call's own echo, to confirm the establish took effect,
    # and check its actual content (the pool id), not just that some rule exists.
    established_pools = _poll_until(
        lambda: [r.get("SourceIpamPoolId") for r in _read_allocation_rules(ec2, policy_id, ctx.region, "eip")],
        lambda pools: pools == [pool_id],
        timeout_s=30,
        interval_s=3,
    )
    if established_pools != [pool_id]:
        raise AssertionError(
            f"GetIpamPolicyAllocationRules (independent read) reports {established_pools!r} for eip, "
            f"expected [{pool_id!r}], after ModifyIpamPolicyAllocationRules reported the establish "
            "call succeeded"
        )

    # success path: explicitly clear the allocation rules for the eip resource type in this locale.
    #
    # The rule just established above is itself asynchronous to propagate:
    # ModifyIpamPolicyAllocationRules can spuriously report
    # InvalidIpamPolicyAllocationRules.NotFound for a few seconds after the
    # creating call returned, because the new rule hasn't yet become visible
    # to subsequent modify calls. Poll (retrying only on that specific error
    # code) until the clear succeeds.

    def _try_clear():
        try:
            return ec2.modify_ipam_policy_allocation_rules(
                IpamPolicyId=policy_id, Locale=ctx.region, ResourceType="eip", AllocationRules=[]
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidIpamPolicyAllocationRules.NotFound":
                return None
            raise

    resp = _poll_until(_try_clear, lambda r: r is not None, timeout_s=60, interval_s=5)
    if resp is None:
        raise AssertionError(
            "newly-established allocation rule never propagated far enough to be clearable "
            "within the timeout"
        )
    assert "IpamPolicyDocument" in resp
    doc = resp["IpamPolicyDocument"]
    assert doc.get("IpamPolicyId") == policy_id, (
        f"expected the modify response to echo IpamPolicyId={policy_id!r}, got {doc.get('IpamPolicyId')!r}"
    )

    # Independent terminal read, again: confirm the clear actually emptied the rule set at the
    # destination (no more SourceIpamPoolId for eip) rather than trusting the mutating call's own
    # response.
    cleared_rules = _poll_until(
        lambda: _read_allocation_rules(ec2, policy_id, ctx.region, "eip"),
        lambda rules: rules == [],
        timeout_s=30,
        interval_s=3,
    )
    if cleared_rules != []:
        raise AssertionError(
            f"GetIpamPolicyAllocationRules (independent read) still reports {cleared_rules!r} for eip "
            "after ModifyIpamPolicyAllocationRules reported the clear succeeded"
        )

    # error boundary: resource type outside the alb|eip|rds|rnat enum
    code, message = _error(
        lambda: ec2.modify_ipam_policy_allocation_rules(
            IpamPolicyId=policy_id, Locale=ctx.region, ResourceType="not-a-resource-type", AllocationRules=[]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "The resource type not-a-resource-type is not valid.", message


# ===== helpers (self-contained) =====


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _read_allocation_rules(ec2, policy_id, locale, resource_type):
    """The independent read: GetIpamPolicyAllocationRules, not ModifyIpamPolicyAllocationRules's own echo."""
    resp = ec2.get_ipam_policy_allocation_rules(IpamPolicyId=policy_id, Locale=locale, ResourceType=resource_type)
    rules = []
    for doc in resp.get("IpamPolicyDocuments", []):
        if doc.get("Locale") == locale and doc.get("ResourceType") == resource_type:
            rules.extend(doc.get("AllocationRules", []))
    return rules


def _create_ipam_pool(ctx, ec2, scope_id):
    name = ctx.unique_name("sim2real-behav-ipam-pool-")
    pool_id = ec2.create_ipam_pool(
        IpamScopeId=scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        TagSpecifications=[{"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": name}]}],
    )["IpamPool"]["IpamPoolId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id))
    pool = _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0],
        lambda p: p["State"] == "create-complete",
        timeout_s=60,
        interval_s=3,
    )
    assert pool is not None and pool["State"] == "create-complete", "IPAM pool never reached create-complete"
    return pool_id


def _create_ipam(ctx, ec2):
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]

    def _cleanup():
        # The IPAM refuses deletion while its policy delete is still settling; retry, never swallow.
        _delete_with_retry(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True), not_found="InvalidIpamId.NotFound")

    ctx.on_cleanup(_cleanup)

    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=90,
        interval_s=3,
    )
    assert ipam is not None and ipam["State"] == "create-complete", "IPAM never reached create-complete"
    return ipam_id, ipam["PrivateDefaultScopeId"], ipam["PublicDefaultScopeId"]


def _delete_with_retry(delete, *, not_found, timeout_s=300.0, interval_s=10.0):
    """Run a teardown delete until it lands or the resource is gone; raise once the deadline passes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == not_found:
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
