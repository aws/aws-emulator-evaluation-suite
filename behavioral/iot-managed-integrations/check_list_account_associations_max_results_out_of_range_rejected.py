"""list-account-associations-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-account-associations-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot-managed-integrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAccountAssociations sent with MaxResults 0 and 1001 (client validation off) fails with
    ValidationException and the exact range message for each bound, while a valid call returns
    Items."""
    iot = _iot_client(ctx, validate_params=False)

    too_low_code, too_low_code_msg = _error(lambda: iot.list_account_associations(MaxResults=0))
    assert too_low_code == "ValidationException", f"expected ValidationException for MaxResults=0, got {too_low_code!r}"
    assert too_low_code_msg == "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value greater than or equal to 1", too_low_code_msg

    too_high_code, too_high_code_msg = _error(lambda: iot.list_account_associations(MaxResults=1001))
    assert too_high_code == "ValidationException", f"expected ValidationException for MaxResults=1001, got {too_high_code!r}"
    assert too_high_code_msg == "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 1000", too_high_code_msg

    # Positive control: a value inside the documented range succeeds.
    resp = iot.list_account_associations(MaxResults=1)
    assert "Items" in resp, f"expected an Items key in the response, got {sorted(resp)!r}"


def _iot_client(ctx, *, validate_params: bool = True):
    """iot-managed-integrations is offered in ca-central-1 and eu-west-1 only, so the client pins
    the region. ``validate_params=False`` turns off botocore's client-side validation so the
    out-of-range MaxResults values reach the service."""
    config = None if validate_params else Config(parameter_validation=False)
    return ctx.client("iot-managed-integrations", region="eu-west-1", config=config)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
