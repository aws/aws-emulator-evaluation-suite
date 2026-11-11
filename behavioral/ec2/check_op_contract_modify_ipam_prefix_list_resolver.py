"""op-contract-modify-ipam-prefix-list-resolver."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-ipam-prefix-list-resolver"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamPrefixListResolver updates the description, echoed and read back; an unknown resolver
    id fails with InvalidIpamPrefixListResolverId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "create_ipam_prefix_list_resolver") or not hasattr(
        ec2, "modify_ipam_prefix_list_resolver"
    ):
        raise AssertionError("botocore in this environment lacks the IPAM prefix list resolver APIs")

    ipam_id, _private_scope_id, _public_scope_id = _create_ipam(ctx, ec2)
    try:
        ec2.modify_ipam(IpamId=ipam_id, Tier="advanced")
    except Exception as exc:  # pragma: no cover - environment-dependent premium feature
        raise AssertionError(f"could not enable IPAM advanced tier: {exc}")

    resolver_name = ctx.unique_name("sim2real-behav-plr-")
    try:
        resolver = ec2.create_ipam_prefix_list_resolver(
            IpamId=ipam_id,
            AddressFamily="ipv4",
            Description="initial",
            TagSpecifications=[
                {"ResourceType": "ipam-prefix-list-resolver", "Tags": [{"Key": "Name", "Value": resolver_name}]}
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

    # newly-created resolvers start in create-in-progress and reject modification
    # until the resolver reaches create-complete.
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

    # success path
    resp = ec2.modify_ipam_prefix_list_resolver(
        IpamPrefixListResolverId=resolver_id, Description="updated-by-sim2real"
    )
    updated = resp["IpamPrefixListResolver"]
    assert updated["Description"] == "updated-by-sim2real", (
        f"expected mutate response Description 'updated-by-sim2real', got {updated['Description']!r}"
    )
    assert updated["IpamPrefixListResolverId"] == resolver_id, (
        f"expected mutate response id {resolver_id!r}, got {updated['IpamPrefixListResolverId']!r}"
    )

    # independent read at the destination: the update must be visible through a
    # different operation than the one that mutated, not just echoed back by it.
    reread = ec2.describe_ipam_prefix_list_resolvers(IpamPrefixListResolverIds=[resolver_id])[
        "IpamPrefixListResolvers"
    ][0]
    assert reread["Description"] == "updated-by-sim2real", (
        f"describe_ipam_prefix_list_resolvers did not persist the update, got {reread['Description']!r}"
    )

    # error boundary: unknown resolver id
    code, message = _error(
        lambda: ec2.modify_ipam_prefix_list_resolver(
            IpamPrefixListResolverId="ipam-plr-00000000000000000", Description="x"
        )
    )
    assert code == "InvalidIpamPrefixListResolverId.NotFound", f"expected NotFound code, got {code}"
    assert message == "The ipam-prefix-list-resolver ID 'ipam-plr-00000000000000000' does not exist", message


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
    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-behav-ipam-"),
        OperatingRegions=[{"RegionName": ctx.region}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
