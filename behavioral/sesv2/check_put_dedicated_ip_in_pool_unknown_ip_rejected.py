"""put-dedicated-ip-in-pool-unknown-ip-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-dedicated-ip-in-pool-unknown-ip-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDedicatedIpInPool for an IP address that is not a dedicated IP owned by the
    account is rejected with NotFoundException, the pool stays empty (no membership was
    created), and the rest of the dedicated-IP-pool management path still works."""
    sesv2 = ctx.client("sesv2")
    pool_name = ctx.unique_name("sim2real-dip-pool-")
    sesv2.create_dedicated_ip_pool(PoolName=pool_name, ScalingMode="STANDARD")
    ctx.on_cleanup(lambda: sesv2.delete_dedicated_ip_pool(PoolName=pool_name))

    bogus_ip = "198.51.100.77"  # TEST-NET-2 (RFC 5737), never a real dedicated IP
    err = _error(
        lambda: sesv2.put_dedicated_ip_in_pool(Ip=bogus_ip, DestinationPoolName=pool_name)
    )
    expected = ("NotFoundException", f"Could not find dedicated IP <{bogus_ip}> under this account.")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # effect absent: the pool is still empty, no membership was created
    ips = sesv2.get_dedicated_ips(PoolName=pool_name)["DedicatedIps"]
    assert ips == []

    # positive control: the pool management path itself works fine
    fetched = sesv2.get_dedicated_ip_pool(PoolName=pool_name)["DedicatedIpPool"]
    assert fetched["PoolName"] == pool_name


def _error(fn):
    """Return the rejected call's (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
