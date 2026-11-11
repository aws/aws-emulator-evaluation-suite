"""hub-configuration-invalid-expiry-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hub-configuration-invalid-expiry-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot-managed-integrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutHubConfiguration rejects HubTokenTimerExpirySettingInSeconds below the documented
    minimum of 1 and does not change the stored setting; a valid value is accepted and
    persists (positive control)."""
    iot = _iot_client(ctx)

    original = _get_current_value(iot)
    if original is not None:
        ctx.on_cleanup(lambda: iot.put_hub_configuration(HubTokenTimerExpirySettingInSeconds=original))

    baseline_value = 7200
    iot.put_hub_configuration(HubTokenTimerExpirySettingInSeconds=baseline_value)
    ctx.on_cleanup(lambda: iot.put_hub_configuration(HubTokenTimerExpirySettingInSeconds=baseline_value))
    seen = iot.get_hub_configuration()["HubTokenTimerExpirySettingInSeconds"]
    assert seen == baseline_value, f"expected baseline {baseline_value}, got {seen}"

    code, code_msg = _error(lambda: iot.put_hub_configuration(HubTokenTimerExpirySettingInSeconds=0))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert code_msg == "1 validation error detected: Value at 'hubTokenTimerExpirySettingInSeconds' failed to satisfy constraint: Member must have value greater than or equal to 1", code_msg

    # Effect absent: the invalid call did not change the stored setting.
    unchanged = iot.get_hub_configuration()["HubTokenTimerExpirySettingInSeconds"]
    assert unchanged == baseline_value, f"expected unchanged {baseline_value}, got {unchanged}"

    # Positive control: a different valid value is accepted and persists.
    other_value = 3600
    iot.put_hub_configuration(HubTokenTimerExpirySettingInSeconds=other_value)
    persisted = iot.get_hub_configuration()["HubTokenTimerExpirySettingInSeconds"]
    assert persisted == other_value, f"expected {other_value} to persist, got {persisted}"


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the
    # runner's default region (us-west-2) has no endpoint for it, so pin the region via
    # ctx.client's region override, which keeps the run's credentials and endpoint
    # routing (a bare boto3.client() would use the ambient credential chain instead).
    #
    # HubTokenTimerExpirySettingInSeconds carries only a client-side smithy.api#range(min=1)
    # trait -- botocore enforces it locally via ParamValidationError before any request is
    # serialized, so the invalid call below would never reach AWS. parameter_validation=False
    # lets the deliberately-invalid value go over the wire so the assertion tests the SERVICE's
    # own rejection, not botocore's.
    return ctx.client(
        "iot-managed-integrations",
        region="eu-west-1",
        config=Config(parameter_validation=False),
    )
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _get_current_value(iot):
    try:
        return iot.get_hub_configuration()["HubTokenTimerExpirySettingInSeconds"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
