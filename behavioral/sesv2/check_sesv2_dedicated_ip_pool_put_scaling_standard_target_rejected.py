"""sesv2-dedicated-ip-pool-put-scaling-standard-target-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sesv2-dedicated-ip-pool-put-scaling-standard-target-rejected"
GROUP = "dedicated-ip-v2"
SERVICES = ["sesv2"]

_BAD_SCALING_MODE = ("BadRequestException", "The ScalingMode parameter is invalid.")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDedicatedIpPoolScalingAttributes(STANDARD) is rejected on a pool that was never
    MANAGED, on a MANAGED pool and on a pool name that was never created, each unchanged by
    the call; the same pool accepts MANAGED right after.
    """
    ses = ctx.client("sesv2")

    pool_std = ctx.unique_name("sim2real-behav-ippoolstd-")
    ses.create_dedicated_ip_pool(PoolName=pool_std)
    ctx.on_cleanup(lambda: ses.delete_dedicated_ip_pool(PoolName=pool_std))
    std_before = ses.get_dedicated_ip_pool(PoolName=pool_std)["DedicatedIpPool"]
    assert std_before["ScalingMode"] == "STANDARD", (
        f"expected a freshly created pool to default to STANDARD, got {std_before['ScalingMode']!r}"
    )

    pool_mgd = ctx.unique_name("sim2real-behav-ippoolmgd-")
    ses.create_dedicated_ip_pool(PoolName=pool_mgd, ScalingMode="MANAGED")
    ctx.on_cleanup(lambda: ses.delete_dedicated_ip_pool(PoolName=pool_mgd))
    mgd_before = ses.get_dedicated_ip_pool(PoolName=pool_mgd)["DedicatedIpPool"]
    assert mgd_before["ScalingMode"] == "MANAGED", (
        f"expected a pool created with ScalingMode=MANAGED to read back MANAGED, "
        f"got {mgd_before['ScalingMode']!r}"
    )

    # PUT STANDARD is refused on a pool that has never been MANAGED: the refusal is not
    # about downgrading a transition, it is about STANDARD never being a valid Put target.
    expect_error(
        lambda: ses.put_dedicated_ip_pool_scaling_attributes(PoolName=pool_std, ScalingMode="STANDARD"),
        *_BAD_SCALING_MODE,
    )
    std_after_refusal = ses.get_dedicated_ip_pool(PoolName=pool_std)["DedicatedIpPool"]
    assert std_after_refusal["ScalingMode"] == "STANDARD", (
        f"expected the refused call to leave the pool at STANDARD, got {std_after_refusal['ScalingMode']!r}"
    )

    # PUT STANDARD is refused the same way on an already-MANAGED pool.
    expect_error(
        lambda: ses.put_dedicated_ip_pool_scaling_attributes(PoolName=pool_mgd, ScalingMode="STANDARD"),
        *_BAD_SCALING_MODE,
    )
    mgd_after_refusal = ses.get_dedicated_ip_pool(PoolName=pool_mgd)["DedicatedIpPool"]
    assert mgd_after_refusal["ScalingMode"] == "MANAGED", (
        f"expected the refused call to leave the pool at MANAGED, got {mgd_after_refusal['ScalingMode']!r}"
    )

    # PUT STANDARD is refused the same way against a pool name that was never created.
    pool_missing = ctx.unique_name("sim2real-behav-ippoolmissing-")
    expect_error(
        lambda: ses.put_dedicated_ip_pool_scaling_attributes(PoolName=pool_missing, ScalingMode="STANDARD"),
        *_BAD_SCALING_MODE,
    )
    expect_error(
        lambda: ses.get_dedicated_ip_pool(PoolName=pool_missing),
        "NotFoundException", f"The requested pool <{pool_missing}> does not exist.",
    )

    # positive control: the same STANDARD pool accepts MANAGED as a Put target right after.
    ses.put_dedicated_ip_pool_scaling_attributes(PoolName=pool_std, ScalingMode="MANAGED")
    std_final = ses.get_dedicated_ip_pool(PoolName=pool_std)["DedicatedIpPool"]
    assert std_final["ScalingMode"] == "MANAGED", (
        f"expected PutDedicatedIpPoolScalingAttributes(MANAGED) to take effect, "
        f"got {std_final['ScalingMode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
