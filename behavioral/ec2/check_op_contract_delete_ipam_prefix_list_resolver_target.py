"""op-contract-delete-ipam-prefix-list-resolver-target."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-ipam-prefix-list-resolver-target"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamPrefixListResolverTarget with DryRun answers DryRunOperation and leaves the target; the
    real call deletes it, and deleting it again fails with
    InvalidIpamPrefixListResolverTargetId.NotFound (exact messages)."""
    ec2 = ctx.client("ec2")

    if not hasattr(ec2, "create_ipam_prefix_list_resolver_target"):
        raise AssertionError(
            "unreachable: installed boto3 does not expose "
            "CreateIpamPrefixListResolverTarget/DeleteIpamPrefixListResolverTarget "
            "(too new for this SDK version)"
        )

    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-ipam-plrt-"),
        OperatingRegions=[{"RegionName": ctx.region}],
        Tier="advanced",
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )

    pl = ec2.create_managed_prefix_list(
        PrefixListName=ctx.unique_name("sim2real-plrt-pl-"),
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
        resolver = ec2.create_ipam_prefix_list_resolver(
            IpamId=ipam_id, AddressFamily="ipv4"
        )["IpamPrefixListResolver"]
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

    target = _poll_until(
        lambda: ec2.describe_ipam_prefix_list_resolver_targets(
            IpamPrefixListResolverTargetIds=[target_id]
        )["IpamPrefixListResolverTargets"][0],
        lambda t: t["State"] == "create-complete",
        timeout_s=90,
    )
    assert target["PrefixListId"] == pl_id

    # error boundary: DryRun short-circuits with DryRunOperation, target survives
    code, message = _error(
        lambda: ec2.delete_ipam_prefix_list_resolver_target(
            IpamPrefixListResolverTargetId=target_id, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    still_there = ec2.describe_ipam_prefix_list_resolver_targets(
        IpamPrefixListResolverTargetIds=[target_id]
    )["IpamPrefixListResolverTargets"][0]
    assert still_there["State"] == "create-complete"

    # success path: real delete removes the target
    resp = ec2.delete_ipam_prefix_list_resolver_target(
        IpamPrefixListResolverTargetId=target_id
    )
    assert resp["IpamPrefixListResolverTarget"]["IpamPrefixListResolverTargetId"] == target_id

    _poll_until(
        lambda: _describe_targets_tolerant(ec2, target_id),
        lambda ts: (not ts) or ts[0]["State"] == "delete-complete",
        timeout_s=90,
    )

    # post-delete negative: the same delete call, which demonstrably worked
    # above, now fails against the dead id with the specific not-found code.
    code, message = _error(
        lambda: ec2.delete_ipam_prefix_list_resolver_target(
            IpamPrefixListResolverTargetId=target_id
        )
    )
    assert code == "InvalidIpamPrefixListResolverTargetId.NotFound", f"unexpected code re-deleting {code!r}"
    assert message == f"The ipam-prefix-list-resolver-target ID '{target_id}' does not exist", f"unexpected message {message!r}"


# ===== helpers =====
def _describe_targets_tolerant(ec2, target_id):
    # once the target is truly gone, DescribeIpamPrefixListResolverTargets raises
    # NotFound instead of returning an empty list - treat that as "deleted" for polling.
    try:
        return ec2.describe_ipam_prefix_list_resolver_targets(
            IpamPrefixListResolverTargetIds=[target_id]
        )["IpamPrefixListResolverTargets"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamPrefixListResolverTargetId.NotFound":
            return []
        raise


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


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
