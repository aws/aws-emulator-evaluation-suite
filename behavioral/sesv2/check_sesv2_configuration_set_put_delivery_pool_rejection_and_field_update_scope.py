"""sesv2-configuration-set-put-delivery-pool-rejection-and-field-update-scope."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sesv2-configuration-set-put-delivery-pool-rejection-and-field-update-scope"
GROUP = "configuration-set-v2"
SERVICES = ["sesv2"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutConfigurationSetDeliveryOptions refuses a sending pool that does not exist, leaves
    delivery options unchanged, then succeeds once the pool exists; a later put that sets only
    TlsPolicy and MaxDeliverySeconds reads back both exactly and pins what happens to the pool.
    """
    ses = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-v2del-")
    ses.create_configuration_set(ConfigurationSetName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda _k=name: ses.delete_configuration_set(ConfigurationSetName=_k))

    baseline = ses.get_configuration_set(ConfigurationSetName=name).get("DeliveryOptions", {})
    assert baseline.get("SendingPoolName") is None, f"expected no sending pool on a fresh set, got {baseline!r}"

    ghost_pool = ctx.unique_name("sim2real-behav-v2delghost-")
    _UNKNOWN_POOL = ("BadRequestException", f"SendingPool <{ghost_pool}> doesn't exist")
    expect_error(
        lambda: ses.put_configuration_set_delivery_options(ConfigurationSetName=name, SendingPoolName=ghost_pool),
        *_UNKNOWN_POOL,
    )
    after_refusal = ses.get_configuration_set(ConfigurationSetName=name).get("DeliveryOptions", {})
    assert after_refusal == baseline, f"rejected put changed delivery options: {after_refusal!r} != {baseline!r}"

    pool = ctx.unique_name("sim2real-behav-v2delpool-")
    ses.create_dedicated_ip_pool(PoolName=pool, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda _k=pool: ses.delete_dedicated_ip_pool(PoolName=_k))

    ses.put_configuration_set_delivery_options(ConfigurationSetName=name, SendingPoolName=pool)
    after_pool = ses.get_configuration_set(ConfigurationSetName=name).get("DeliveryOptions", {})
    assert after_pool.get("SendingPoolName") == pool, (
        f"identical put did not succeed once the pool existed: {after_pool!r}"
    )

    ses.put_configuration_set_delivery_options(ConfigurationSetName=name, TlsPolicy="REQUIRE", MaxDeliverySeconds=300)
    final = ses.get_configuration_set(ConfigurationSetName=name).get("DeliveryOptions", {})
    assert final["TlsPolicy"] == "REQUIRE", f"TlsPolicy not stored: {final!r}"
    assert final["MaxDeliverySeconds"] == 300, f"MaxDeliverySeconds not stored: {final!r}"
    assert final.get("SendingPoolName") is None, (
        f"a put naming TlsPolicy and MaxDeliverySeconds but not SendingPoolName left a stale "
        f"pool in place: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
