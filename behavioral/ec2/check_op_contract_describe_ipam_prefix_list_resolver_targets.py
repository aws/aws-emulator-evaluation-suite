"""op-contract-describe-ipam-prefix-list-resolver-targets."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describe-ipam-prefix-list-resolver-targets"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamPrefixListResolverTargets answers with a list, scoped to a real resolver returns its
    target, and a well-formed unknown resolver ID fails with InvalidIpamPrefixListResolverId.NotFound;
    DryRun answers DryRunOperation (exact messages)."""

    ec2 = ctx.client("ec2")
    required_ops = (
        "describe_ipam_prefix_list_resolver_targets",
        "create_ipam_prefix_list_resolver",
        "create_ipam_prefix_list_resolver_target",
    )
    if not all(hasattr(ec2, op) for op in required_ops):
        raise AssertionError(
            "unreachable: installed botocore lacks the IPAM prefix list resolver target APIs"
        )

    # Success path: no filter -> well-formed (possibly empty) list.
    resp = ec2.describe_ipam_prefix_list_resolver_targets()
    assert "IpamPrefixListResolverTargets" in resp, f"missing key in response: {sorted(resp)}"
    targets = resp["IpamPrefixListResolverTargets"]
    assert isinstance(targets, list)
    for item in targets:
        assert "IpamPrefixListResolverTargetId" in item

    # Positive control: create a real resolver + target so the resolver-id filter
    # has something valid to scope to. Without this, "rejects a nonexistent
    # resolver id" is indistinguishable from "rejects every filtered describe".
    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-ipam-plrtc-"),
        OperatingRegions=[{"RegionName": ctx.region}],
        Tier="advanced",
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=90,
    )

    pl = ec2.create_managed_prefix_list(
        PrefixListName=ctx.unique_name("sim2real-plrtc-pl-"),
        MaxEntries=5,
        AddressFamily="IPv4",
    )["PrefixList"]
    pl_id = pl["PrefixListId"]
    ctx.on_cleanup(lambda: _safe_delete_pl(ec2, pl_id))

    _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0],
        lambda p: p["State"] == "create-complete",
        timeout_s=60,
    )

    try:
        resolver = ec2.create_ipam_prefix_list_resolver(IpamId=ipam_id, AddressFamily="ipv4")[
            "IpamPrefixListResolver"
        ]
    except ClientError as exc:
        raise AssertionError(
            f"unreachable: CreateIpamPrefixListResolver rejected: {exc.response['Error']['Code']}"
        ) from exc
    resolver_id = resolver["IpamPrefixListResolverId"]
    ctx.on_cleanup(lambda: _safe_delete_resolver(ec2, resolver_id))

    _poll_until(
        lambda: ec2.describe_ipam_prefix_list_resolvers(IpamPrefixListResolverIds=[resolver_id])[
            "IpamPrefixListResolvers"
        ][0],
        lambda r: r["State"] == "create-complete",
        timeout_s=90,
    )

    target = ec2.create_ipam_prefix_list_resolver_target(
        IpamPrefixListResolverId=resolver_id,
        PrefixListId=pl_id,
        PrefixListRegion=ctx.region,
        TrackLatestVersion=True,
    )["IpamPrefixListResolverTarget"]
    target_id = target["IpamPrefixListResolverTargetId"]
    ctx.on_cleanup(lambda: _safe_delete_target(ec2, target_id))

    _poll_until(
        lambda: ec2.describe_ipam_prefix_list_resolver_targets(
            IpamPrefixListResolverTargetIds=[target_id]
        )["IpamPrefixListResolverTargets"][0],
        lambda t: t["State"] == "create-complete",
        timeout_s=90,
    )

    # The resolver-id filter must actually scope to the real target: a valid,
    # in-use resolver id returns exactly the target(s) attached to it.
    scoped = ec2.describe_ipam_prefix_list_resolver_targets(
        IpamPrefixListResolverId=resolver_id
    )["IpamPrefixListResolverTargets"]
    scoped_ids = {t["IpamPrefixListResolverTargetId"] for t in scoped}
    assert target_id in scoped_ids, f"expected {target_id} in resolver-scoped targets, got {scoped_ids}"
    for t in scoped:
        assert t["IpamPrefixListResolverId"] == resolver_id, (
            f"resolver-id filter leaked a target from another resolver: {t}"
        )

    # The resolver ID is a scoping lookup, not a filter: a well-formed nonexistent resolver ID fails with
    # NotFound instead of returning an empty list, unlike the real resolver ID above.
    code, message = _error(
        lambda: ec2.describe_ipam_prefix_list_resolver_targets(
            IpamPrefixListResolverId="ipam-plr-0000000000000000"
        )
    )
    assert code == "InvalidIpamPrefixListResolverId.NotFound", f"expected NotFound, got {code!r}"
    assert message == (
        "The specified IPAM Prefix List Resolver does not exist."
    ), f"unexpected InvalidIpamPrefixListResolverId.NotFound message: {message!r}"

    # Error boundary: DryRun.
    code, message = _error(lambda: ec2.describe_ipam_prefix_list_resolver_targets(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe_delete_pl(ec2, pl_id):
    try:
        ec2.delete_managed_prefix_list(PrefixListId=pl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPrefixListID.NotFound":
            raise


def _safe_delete_resolver(ec2, resolver_id):
    try:
        ec2.delete_ipam_prefix_list_resolver(IpamPrefixListResolverId=resolver_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamPrefixListResolverId.NotFound":
            raise


def _safe_delete_target(ec2, target_id):
    try:
        ec2.delete_ipam_prefix_list_resolver_target(IpamPrefixListResolverTargetId=target_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamPrefixListResolverTargetId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
