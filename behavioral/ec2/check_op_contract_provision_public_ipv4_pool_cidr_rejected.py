"""op-contract-provision-public-ipv4-pool-cidr-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-provision-public-ipv4-pool-cidr-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ProvisionPublicIpv4PoolCidr against a real IPAM pool fails with InvalidPublicIpv4Pool.NotFound and
    its exact message for an unknown public IPv4 pool id, and the IPAM pool has no CIDRs afterwards."""
    ec2 = ctx.client("ec2")
    ipam, created = _get_or_create_ipam(ctx, ec2)
    ipam_id = ipam["IpamId"]
    if created:
        ctx.on_cleanup(lambda: _delete_ipam_retrying(ec2, ipam_id))

    pool_name = ctx.unique_name("sim2real-behav-pubpool-")
    pool = ec2.create_ipam_pool(
        IpamScopeId=ipam["PublicDefaultScopeId"],
        AddressFamily="ipv4",
        Locale=ctx.region,
        PublicIpSource="byoip",
        Description=pool_name,
        TagSpecifications=[{"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": pool_name}]}],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id))
    assert _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"]
        == "create-complete",
        timeout_s=60,
        interval_s=3,
    ), "IPAM public pool never reached create-complete"

    err, message, _ = _client_error(
        lambda: ec2.provision_public_ipv4_pool_cidr(
            IpamPoolId=pool_id, PoolId="ipv4pool-ec2-00000000000000000", NetmaskLength=24
        )
    )
    assert err == "InvalidPublicIpv4Pool.NotFound", f"expected InvalidPublicIpv4Pool.NotFound, got {err!r}"
    assert message == "The pool ID 'ipv4pool-ec2-00000000000000000' does not exist.", f"unexpected {err} message: {message!r}"

    # independent read at the destination: a rejected provision must leave no CIDR
    # attached to the real pool it targeted.
    cidrs_after = ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]
    assert cidrs_after == [], (
        f"a rejected ProvisionPublicIpv4PoolCidr must not leave a CIDR provisioned into the pool, got {cidrs_after}"
    )


def _get_or_create_ipam(ctx, ec2):
    """Return (ipam, created) for an IPAM to run this rejection test against.

    Accounts have a default limit of one IPAM per region; if a prior run (or a
    concurrently running check) already created one, reuse it instead of
    failing the whole check with ResourceLimitExceeded.
    """
    from botocore.exceptions import ClientError

    ipam_name = ctx.unique_name("sim2real-behav-ipam-")
    try:
        ipam = ec2.create_ipam(
            Description=ipam_name,
            OperatingRegions=[{"RegionName": ctx.region}],
            TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": ipam_name}]}],
        )["Ipam"]
        return ipam, True
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
            raise
        existing = ec2.describe_ipams()["Ipams"]
        if not existing:
            raise
        return existing[0], False


def _delete_ipam_retrying(ec2, ipam_id, *, timeout_s=300.0, interval_s=5.0):
    """Delete the IPAM, retrying while a just-deleted pool still holds its public scope.

    DeleteIpamPool returns while the pool is still delete-in-progress, so an immediate
    DeleteIpam answers DependencyViolation. Any other error, or a timeout, propagates.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until(probe, *, timeout_s=60.0, interval_s=3.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
