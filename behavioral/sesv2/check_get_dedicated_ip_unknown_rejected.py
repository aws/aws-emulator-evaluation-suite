"""get-dedicated-ip-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-dedicated-ip-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDedicatedIp for an IP address that is not associated with the account is
    rejected with NotFoundException, while GetDedicatedIpPool for a real pool in the same
    account still succeeds."""
    sesv2 = ctx.client("sesv2")
    bogus_ip = "203.0.113.42"  # TEST-NET-3 (RFC 5737), never a real dedicated IP
    err = _error(lambda: sesv2.get_dedicated_ip(Ip=bogus_ip))
    assert err.get("Code") == "NotFoundException", (
        f"GetDedicatedIp for {bogus_ip!r}, which is not a dedicated IP owned by this account, "
        f"returned {err!r}, expected 'NotFoundException'"
    )
    expected = f"Could not find dedicated IP <{bogus_ip}> under this account."
    assert err.get("Message") == expected, f"expected message {expected!r}, got {err.get('Message')!r}"

    pool_name = ctx.unique_name("sim2real-dip-pool-")
    sesv2.create_dedicated_ip_pool(
        PoolName=pool_name,
        ScalingMode="STANDARD",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: sesv2.delete_dedicated_ip_pool(PoolName=pool_name))

    # positive control: a real resource in the same dedicated-IP API surface is readable
    fetched = sesv2.get_dedicated_ip_pool(PoolName=pool_name)["DedicatedIpPool"]
    assert fetched["PoolName"] == pool_name, (
        f"GetDedicatedIpPool for the pool this check just created returned "
        f"{fetched.get('PoolName')!r}, expected {pool_name!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
