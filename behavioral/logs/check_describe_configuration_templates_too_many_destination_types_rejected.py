"""describe-configuration-templates-too-many-destination-types-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "describe-configuration-templates-too-many-destination-types-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationTemplates with more deliveryDestinationTypes than the list's own
    maximum of 4 is rejected with ValidationException naming the length constraint."""
    logs = ctx.client("logs")

    # Positive control: exactly the 4 modelled destination types is within bounds, and every
    # entry it returns names one of the 4 types requested.
    all_types = ["S3", "CWL", "FH", "XRAY"]
    ok = logs.describe_configuration_templates(deliveryDestinationTypes=all_types)
    returned_types = {t["deliveryDestinationType"] for t in ok["configurationTemplates"]}
    assert returned_types <= set(all_types), (
        f"expected every returned template's deliveryDestinationType to be one of "
        f"{all_types}, got {sorted(returned_types)}"
    )

    # Negative: 5 entries exceeds the list's own max length of 4 (duplicates are still 5
    # elements; the constraint is on list length, not on distinct values).
    too_many = ["S3", "S3", "S3", "S3", "S3"]
    code, message = _error(
        lambda: logs.describe_configuration_templates(deliveryDestinationTypes=too_many)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for 5 deliveryDestinationTypes (max 4), got "
        f"{code!r} {message!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'deliveryDestinationTypes' failed to satisfy "
        "constraint: Member must have length less than or equal to 4"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
