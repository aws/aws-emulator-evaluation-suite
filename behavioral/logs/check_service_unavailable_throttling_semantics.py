"""service-unavailable-throttling-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-unavailable-throttling-semantics"
GROUP = 'overly-permissive'
SERVICES = ['logs']


_LIMIT_MESSAGE = (
    "1 validation error detected: Value at 'limit' failed to satisfy constraint: "
    "Member must have value less than or equal to 50"
)


def _reject_code(fn):
    """Return the service's (Code, Message) for a ClientError; a call that succeeds raises.
    ParamValidationError is not caught: a local SDK rejection is not service-side evidence.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Four Describe* delivery-family operations reject limit=51 server-side with the exact
    limit-range ValidationException (botocore checks only the minimum locally), and
    DescribeDeliveries(limit=5) succeeds.
    """
    svc = ctx.client("logs")
    out_of_range_limit = 51

    code_templates, msg = _reject_code(lambda: svc.describe_configuration_templates(limit=out_of_range_limit))
    assert (code_templates, msg) == ("ValidationException", _LIMIT_MESSAGE), (
        f"DescribeConfigurationTemplates(limit={out_of_range_limit}, above the documented max of 50): "
        f"expected ValidationException {_LIMIT_MESSAGE!r}, got {code_templates}: {msg!r}"
    )

    code_deliveries, msg = _reject_code(lambda: svc.describe_deliveries(limit=out_of_range_limit))
    assert (code_deliveries, msg) == ("ValidationException", _LIMIT_MESSAGE), (
        f"DescribeDeliveries(limit={out_of_range_limit}, above the documented max of 50): "
        f"expected ValidationException {_LIMIT_MESSAGE!r}, got {code_deliveries}: {msg!r}"
    )

    code_destinations, msg = _reject_code(lambda: svc.describe_delivery_destinations(limit=out_of_range_limit))
    assert (code_destinations, msg) == ("ValidationException", _LIMIT_MESSAGE), (
        f"DescribeDeliveryDestinations(limit={out_of_range_limit}, above the documented max of 50): "
        f"expected ValidationException {_LIMIT_MESSAGE!r}, got {code_destinations}: {msg!r}"
    )

    code_sources, msg = _reject_code(lambda: svc.describe_delivery_sources(limit=out_of_range_limit))
    assert (code_sources, msg) == ("ValidationException", _LIMIT_MESSAGE), (
        f"DescribeDeliverySources(limit={out_of_range_limit}, above the documented max of 50): "
        f"expected ValidationException {_LIMIT_MESSAGE!r}, got {code_sources}: {msg!r}"
    )

    within_range = svc.describe_deliveries(limit=5)
    assert "deliveries" in within_range, (
        f"expected a well-formed DescribeDeliveries call to succeed: {within_range!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
