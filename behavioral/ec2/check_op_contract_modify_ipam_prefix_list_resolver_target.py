"""op-contract-modify-ipam-prefix-list-resolver-target."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-ipam-prefix-list-resolver-target"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamPrefixListResolverTarget pins DesiredVersion to the synced version with
    TrackLatestVersion false, echoed and read back at sync-complete; an unknown target id fails with
    InvalidIpamPrefixListResolverTargetId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    required_ops = (
        "create_ipam_prefix_list_resolver",
        "create_ipam_prefix_list_resolver_target",
        "modify_ipam_prefix_list_resolver_target",
    )
    if not all(hasattr(ec2, op) for op in required_ops):
        raise AssertionError("botocore in this environment lacks the IPAM prefix list resolver target APIs")

    ipam_id, _private_scope_id, _public_scope_id = _create_ipam(ctx, ec2)
    try:
        ec2.modify_ipam(IpamId=ipam_id, Tier="advanced")
    except Exception as exc:  # pragma: no cover - environment-dependent premium feature
        raise AssertionError(f"could not enable IPAM advanced tier: {exc}")

    pl_id = _create_managed_prefix_list(ctx, ec2)

    try:
        resolver = ec2.create_ipam_prefix_list_resolver(
            IpamId=ipam_id,
            AddressFamily="ipv4",
            TagSpecifications=[
                {
                    "ResourceType": "ipam-prefix-list-resolver",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-resolver-")}],
                }
            ],
        )["IpamPrefixListResolver"]
    except Exception as exc:  # pragma: no cover - environment-dependent premium feature
        raise AssertionError(f"IPAM prefix list resolver feature unavailable: {exc}")
    resolver_id = resolver["IpamPrefixListResolverId"]

    def _cleanup_resolver():
        try:
            ec2.delete_ipam_prefix_list_resolver(IpamPrefixListResolverId=resolver_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidIpamPrefixListResolverId.NotFound":
                raise

    ctx.on_cleanup(_cleanup_resolver)

    # newly-created resolvers start in create-in-progress; targets on such a resolver
    # reject modification until the resolver itself reaches create-complete.
    resolver = _poll_until(
        lambda: ec2.describe_ipam_prefix_list_resolvers(IpamPrefixListResolverIds=[resolver_id])[
            "IpamPrefixListResolvers"
        ][0],
        lambda r: r["State"] == "create-complete",
        timeout_s=90,
        interval_s=3,
    )
    assert resolver is not None and resolver["State"] == "create-complete", (
        "IPAM prefix list resolver never reached create-complete"
    )

    target = ec2.create_ipam_prefix_list_resolver_target(
        IpamPrefixListResolverId=resolver_id,
        PrefixListId=pl_id,
        PrefixListRegion=ctx.region,
        TrackLatestVersion=True,
        TagSpecifications=[
            {
                "ResourceType": "ipam-prefix-list-resolver-target",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-target-")}],
            }
        ],
    )["IpamPrefixListResolverTarget"]
    target_id = target["IpamPrefixListResolverTargetId"]

    def _cleanup_target():
        try:
            ec2.delete_ipam_prefix_list_resolver_target(IpamPrefixListResolverTargetId=target_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidIpamPrefixListResolverTargetId.NotFound":
                raise

    ctx.on_cleanup(_cleanup_target)

    # newly-created targets also start in create-in-progress and reject modification
    # until they reach create-complete.
    target = _poll_until(
        lambda: ec2.describe_ipam_prefix_list_resolver_targets(IpamPrefixListResolverTargetIds=[target_id])[
            "IpamPrefixListResolverTargets"
        ][0],
        lambda t: t["State"] == "create-complete",
        timeout_s=90,
        interval_s=3,
    )
    assert target is not None and target["State"] == "create-complete", (
        "IPAM prefix list resolver target never reached create-complete"
    )

    # a version becomes pinnable only once the resolver has actually synced to
    # it while tracking latest -- pinning to a version number nobody has
    # observed yet is rejected with InvalidParameterValue, so the version to
    # pin must come from the target's own reported LastSyncedVersion, not a
    # guessed number.
    target = _poll_until(
        lambda: ec2.describe_ipam_prefix_list_resolver_targets(IpamPrefixListResolverTargetIds=[target_id])[
            "IpamPrefixListResolverTargets"
        ][0],
        lambda t: t.get("LastSyncedVersion") is not None,
        timeout_s=90,
        interval_s=3,
    )
    assert target is not None and target.get("LastSyncedVersion") is not None, (
        f"resolver target never reported a LastSyncedVersion to pin to: {target!r}"
    )
    synced_version = target["LastSyncedVersion"]

    # success path: switch from tracking latest to that observed pinned version
    resp = ec2.modify_ipam_prefix_list_resolver_target(
        IpamPrefixListResolverTargetId=target_id, TrackLatestVersion=False, DesiredVersion=synced_version
    )
    updated = resp["IpamPrefixListResolverTarget"]
    assert updated["TrackLatestVersion"] is False
    assert updated["DesiredVersion"] == synced_version

    # the mutating call's own response only echoes the request; confirm the
    # change actually persisted via an independent read at the destination.
    # Real AWS routes a version pin through sync-in-progress (the resolver
    # re-syncs the prefix list to the pinned version), not modify-in-progress.
    reread = _poll_until(
        lambda: ec2.describe_ipam_prefix_list_resolver_targets(IpamPrefixListResolverTargetIds=[target_id])[
            "IpamPrefixListResolverTargets"
        ][0],
        lambda t: t["State"] not in ("modify-in-progress", "sync-in-progress"),
        timeout_s=90,
        interval_s=3,
    )
    assert reread is not None and reread["State"] == "sync-complete", (
        f"target did not settle into sync-complete after the pin, got {reread!r}"
    )
    assert reread["TrackLatestVersion"] is False, reread
    assert reread["DesiredVersion"] == synced_version, reread

    # error boundary: unknown target id
    code, message = _error(
        lambda: ec2.modify_ipam_prefix_list_resolver_target(
            IpamPrefixListResolverTargetId="ipam-plrt-00000000000000000", TrackLatestVersion=True
        )
    )
    assert code == "InvalidIpamPrefixListResolverTargetId.NotFound", f"expected NotFound code, got {code}"
    assert message == "The ipam-prefix-list-resolver-target ID 'ipam-plrt-00000000000000000' does not exist", message


# ===== helpers =====


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


def _create_ipam(ctx, ec2):
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]

    def _cleanup():
        try:
            ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidIpamId.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=90,
        interval_s=3,
    )
    assert ipam is not None and ipam["State"] == "create-complete", "IPAM never reached create-complete"
    return ipam_id, ipam["PrivateDefaultScopeId"], ipam["PublicDefaultScopeId"]


def _create_managed_prefix_list(ctx, ec2):
    name = ctx.unique_name("sim2real-behav-pl-")
    pl = ec2.create_managed_prefix_list(
        PrefixListName=name,
        MaxEntries=1,
        AddressFamily="IPv4",
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "Name", "Value": name}]}],
    )["PrefixList"]
    pl_id = pl["PrefixListId"]

    def _cleanup():
        try:
            ec2.delete_managed_prefix_list(PrefixListId=pl_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidPrefixListID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    pl = _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0],
        lambda p: p["State"] == "create-complete",
        timeout_s=60,
        interval_s=2,
    )
    assert pl is not None and pl["State"] == "create-complete", "managed prefix list never reached create-complete"
    return pl_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
