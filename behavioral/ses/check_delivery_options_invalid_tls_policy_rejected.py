"""delivery-options-invalid-tls-policy-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delivery-options-invalid-tls-policy-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn() and return the (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected success raises, so a target that accepts a call AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutConfigurationSetDeliveryOptions rejects an unknown TlsPolicy with ValidationError and
    keeps the previously stored valid value (Require)."""
    ses = ctx.client("ses")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-badtls-")
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    ctx.on_cleanup(lambda _n=cfg_name: ses.delete_configuration_set(ConfigurationSetName=_n))

    # Positive control: a modelled TlsPolicy value must land and read back.
    ses.put_configuration_set_delivery_options(
        ConfigurationSetName=cfg_name, DeliveryOptions={"TlsPolicy": "Require"}
    )
    desc0 = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["deliveryOptions"]
    )
    assert desc0.get("DeliveryOptions", {}).get("TlsPolicy") == "Require", (
        f"positive control failed: expected TlsPolicy=Require after a valid put, got {desc0.get('DeliveryOptions')}"
    )

    # Enum violations surface as ValidationError, not the InvalidParameterValue used for bad values.
    err = _err(
        lambda: ses.put_configuration_set_delivery_options(
            ConfigurationSetName=cfg_name, DeliveryOptions={"TlsPolicy": "NotAPolicy"}
        )
    )
    assert err == (
        "ValidationError",
        "1 validation error detected: Value at 'deliveryOptions.tlsPolicy' failed to satisfy "
        "constraint: Member must satisfy enum value set: [Optional, Require]",
    ), (
        f"expected ValidationError for an unknown TlsPolicy, got {err!r}"
    )

    # The prior, positively-controlled value must survive untouched: no leak
    # of the invalid value, and no silent reset to a default.
    desc = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["deliveryOptions"]
    )
    assert desc.get("DeliveryOptions", {}).get("TlsPolicy") == "Require", (
        f"rejected TlsPolicy did not leave the prior value intact: {desc.get('DeliveryOptions')}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
