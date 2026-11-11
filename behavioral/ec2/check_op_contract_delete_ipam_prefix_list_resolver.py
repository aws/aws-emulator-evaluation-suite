"""op-contract-delete-ipam-prefix-list-resolver."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-ipam-prefix-list-resolver"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamPrefixListResolver with DryRun answers DryRunOperation and leaves the resolver; the real
    call deletes it, and deleting it again fails with InvalidIpamPrefixListResolverId.NotFound (exact
    messages)."""
    ec2 = ctx.client("ec2")

    if not hasattr(ec2, "create_ipam_prefix_list_resolver"):
        raise AssertionError(
            "unreachable: installed boto3 does not expose CreateIpamPrefixListResolver/"
            "DeleteIpamPrefixListResolver (too new for this SDK version)"
        )

    ipam = _create_ipam_with_capacity(
        ec2,
        Description=ctx.unique_name("sim2real-ipam-plr-"),
        OperatingRegions=[{"RegionName": ctx.region}],
        Tier="advanced",
        TagSpecifications=[
            {"ResourceType": "ipam", "Tags": [{"Key": "sim2real", "Value": "true"}]}
        ],
    )
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )

    try:
        resolver = ec2.create_ipam_prefix_list_resolver(
            IpamId=ipam_id,
            AddressFamily="ipv4",
            Description=ctx.unique_name("sim2real-plr-"),
            TagSpecifications=[
                {
                    "ResourceType": "ipam-prefix-list-resolver",
                    "Tags": [{"Key": "sim2real", "Value": "true"}],
                }
            ],
        )["IpamPrefixListResolver"]
    except ClientError as exc:
        raise AssertionError(
            f"unreachable: CreateIpamPrefixListResolver rejected in this account/region: "
            f"{exc.response['Error']['Code']}"
        ) from exc

    resolver_id = resolver["IpamPrefixListResolverId"]
    ctx.on_cleanup(lambda: _safe_delete_resolver(ec2, resolver_id))

    resolver = _poll_until(
        lambda: ec2.describe_ipam_prefix_list_resolvers(IpamPrefixListResolverIds=[resolver_id])[
            "IpamPrefixListResolvers"
        ][0],
        lambda r: r["State"] == "create-complete",
        timeout_s=90,
    )

    # error boundary: DryRun short-circuits with DryRunOperation, resolver survives
    code, message = _error(
        lambda: ec2.delete_ipam_prefix_list_resolver(
            IpamPrefixListResolverId=resolver_id, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    still_there = ec2.describe_ipam_prefix_list_resolvers(
        IpamPrefixListResolverIds=[resolver_id]
    )["IpamPrefixListResolvers"][0]
    assert still_there["State"] == "create-complete"

    # success path: a resolver with no targets deletes cleanly
    resp = ec2.delete_ipam_prefix_list_resolver(IpamPrefixListResolverId=resolver_id)
    assert resp["IpamPrefixListResolver"]["IpamPrefixListResolverId"] == resolver_id

    _poll_until(
        lambda: _describe_resolvers_tolerant(ec2, resolver_id),
        lambda rs: (not rs) or rs[0]["State"] == "delete-complete",
        timeout_s=90,
    )

    # the dead id is also refused for further mutation: a second delete is not silently
    # accepted as if the resolver were still live.
    second_code, second_message = _error(
        lambda: ec2.delete_ipam_prefix_list_resolver(IpamPrefixListResolverId=resolver_id)
    )
    assert second_code == "InvalidIpamPrefixListResolverId.NotFound", f"unexpected re-delete code {second_code}"
    assert second_message == f"The ipam-prefix-list-resolver ID '{resolver_id}' does not exist", f"unexpected message {second_message!r}"


# ===== helpers =====
def _reclaim_ipam_quota(ec2):
    # The per-Region IPAM quota can be 1, so an interrupted run's "sim2real-*" IPAM can
    # exhaust it; cascade-delete stale sim2real IPAMs before creating a new one.
    try:
        existing = ec2.describe_ipams()["Ipams"]
    except ClientError:
        return
    stale = [i for i in existing if (i.get("Description") or "").startswith("sim2real-")]
    if not stale:
        return
    for ipam in stale:
        try:
            ec2.delete_ipam(IpamId=ipam["IpamId"], Cascade=True)
        except ClientError:
            pass
    _poll_until(
        lambda: ec2.describe_ipams()["Ipams"],
        lambda ipams: not any(
            (i.get("Description") or "").startswith("sim2real-") for i in ipams
        ),
        timeout_s=120,
    )


def _create_ipam_with_capacity(ec2, **kwargs):
    try:
        return ec2.create_ipam(**kwargs)["Ipam"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
            raise
        _reclaim_ipam_quota(ec2)
        return ec2.create_ipam(**kwargs)["Ipam"]


def _describe_resolvers_tolerant(ec2, resolver_id):
    # once the resolver is truly gone, DescribeIpamPrefixListResolvers raises NotFound
    # instead of returning an empty list - treat that as "deleted" for polling purposes.
    try:
        return ec2.describe_ipam_prefix_list_resolvers(
            IpamPrefixListResolverIds=[resolver_id]
        )["IpamPrefixListResolvers"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamPrefixListResolverId.NotFound":
            return []
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
