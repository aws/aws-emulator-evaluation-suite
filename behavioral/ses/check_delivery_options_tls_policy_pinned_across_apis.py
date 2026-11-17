"""delivery-options-tls-policy-pinned-across-apis."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delivery-options-tls-policy-pinned-across-apis"
GROUP = 'configuration-set'
SERVICES = ['ses', 'sesv2']


def _rejects(fn):
    """The (Code, Message) fn() is refused with; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _v1_tls_policy(ses, name):
    attrs = ses.describe_configuration_set(
        ConfigurationSetName=name, ConfigurationSetAttributeNames=["deliveryOptions"]
    )
    return attrs["DeliveryOptions"]["TlsPolicy"]


def _v2_tls_policy(sesv2, name):
    return sesv2.get_configuration_set(ConfigurationSetName=name)["DeliveryOptions"]["TlsPolicy"]


@tags("axis:rejection", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutConfigurationSetDeliveryOptions TlsPolicy values read back through SESv2
    GetConfigurationSet (REQUIRE/OPTIONAL) and SESv1 DescribeConfigurationSet (Require/Optional); a
    put with no DeliveryOptions clears the block in both; an unknown set is refused, then accepted once created."""
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-delopt-")
    ses.create_configuration_set(ConfigurationSet={"Name": name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=name))

    ses.put_configuration_set_delivery_options(
        ConfigurationSetName=name, DeliveryOptions={"TlsPolicy": "Require"}
    )
    assert _v2_tls_policy(sesv2, name) == "REQUIRE", (
        f"v2 GetConfigurationSet must read back REQUIRE after Require, got "
        f"{_v2_tls_policy(sesv2, name)!r}"
    )
    assert _v1_tls_policy(ses, name) == "Require", (
        f"v1 DescribeConfigurationSet must read back Require after Require, got "
        f"{_v1_tls_policy(ses, name)!r}"
    )

    ses.put_configuration_set_delivery_options(
        ConfigurationSetName=name, DeliveryOptions={"TlsPolicy": "Optional"}
    )
    assert _v2_tls_policy(sesv2, name) == "OPTIONAL", (
        f"v2 GetConfigurationSet must read back OPTIONAL after Optional, got "
        f"{_v2_tls_policy(sesv2, name)!r}"
    )
    assert _v1_tls_policy(ses, name) == "Optional", (
        f"v1 DescribeConfigurationSet must read back Optional after Optional, got "
        f"{_v1_tls_policy(ses, name)!r}"
    )

    ses.put_configuration_set_delivery_options(
        ConfigurationSetName=name, DeliveryOptions={"TlsPolicy": "Require"}
    )
    ses.put_configuration_set_delivery_options(ConfigurationSetName=name)
    after_empty_v2 = sesv2.get_configuration_set(ConfigurationSetName=name)
    after_empty_v1 = ses.describe_configuration_set(
        ConfigurationSetName=name, ConfigurationSetAttributeNames=["deliveryOptions"]
    )
    assert "DeliveryOptions" not in after_empty_v2, (
        f"a put with no DeliveryOptions after Require must clear the block, v2 still has "
        f"{after_empty_v2.get('DeliveryOptions')!r}"
    )
    assert "DeliveryOptions" not in after_empty_v1, (
        f"a put with no DeliveryOptions after Require must clear the block, v1 still has "
        f"{after_empty_v1.get('DeliveryOptions')!r}"
    )

    missing_name = ctx.unique_name("sim2real-behav-delopt-missing-")
    _NOT_FOUND = (
        "ConfigurationSetDoesNotExist",
        f"Configuration set <{missing_name}> does not exist.",
    )
    err = _rejects(
        lambda: ses.put_configuration_set_delivery_options(
            ConfigurationSetName=missing_name, DeliveryOptions={"TlsPolicy": "Require"}
        )
    )
    assert err == _NOT_FOUND, f"expected {_NOT_FOUND}, got {err!r}"

    ses.create_configuration_set(ConfigurationSet={"Name": missing_name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=missing_name))
    ses.put_configuration_set_delivery_options(
        ConfigurationSetName=missing_name, DeliveryOptions={"TlsPolicy": "Require"}
    )
    assert _v2_tls_policy(sesv2, missing_name) == "REQUIRE", (
        f"the identical put must succeed once the configuration set exists, got "
        f"{_v2_tls_policy(sesv2, missing_name)!r} via v2"
    )
    assert _v1_tls_policy(ses, missing_name) == "Require", (
        f"the identical put must succeed once the configuration set exists, got "
        f"{_v1_tls_policy(ses, missing_name)!r} via v1"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
