"""reserved-instance-identifier-validation-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-instance-identifier-validation-rejected"
GROUP = "reserved-instances"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeReservedInstances and DescribeReservedInstanceOfferings each reject a 36-character
    id that is not GUID-shaped with ValidationException quoting the pattern, and a well-formed but
    unknown GUID with ResourceNotFoundException and its own exact message, per operation."""
    os_client = ctx.client("opensearch")

    # Positive control: an always-available, ungated control-plane read proves the client and
    # credentials work, so the rejections below reflect id classification alone.
    os_client.list_domain_names()

    malformed_id = "not-a-valid-reservation-identifier!!"  # 36 chars, not GUID-shaped
    assert len(malformed_id) == 36, malformed_id
    pattern_message = (
        "1 validation error detected: Value '{value}' at '{field}' failed to satisfy "
        r"constraint: Member must satisfy regular expression pattern: "
        r"\p{{XDigit}}{{8}}-\p{{XDigit}}{{4}}-\p{{XDigit}}{{4}}-\p{{XDigit}}{{4}}-\p{{XDigit}}{{12}}"
    )

    code, message = _error(
        lambda: os_client.describe_reserved_instances(ReservedInstanceId=malformed_id)
    )
    assert code == "ValidationException", (
        f"DescribeReservedInstances: expected ValidationException for a non-GUID-shaped id, "
        f"got {code}"
    )
    expected = pattern_message.format(value=malformed_id, field="reservedInstanceId")
    assert message == expected, f"DescribeReservedInstances: got message {message!r}"

    code, message = _error(
        lambda: os_client.describe_reserved_instance_offerings(ReservedInstanceOfferingId=malformed_id)
    )
    assert code == "ValidationException", (
        f"DescribeReservedInstanceOfferings: expected ValidationException for a non-GUID-shaped "
        f"id, got {code}"
    )
    expected = pattern_message.format(value=malformed_id, field="reservedInstanceOfferingId")
    assert message == expected, f"DescribeReservedInstanceOfferings: got message {message!r}"

    missing_id = str(uuid.uuid4())
    code, message = _error(
        lambda: os_client.describe_reserved_instances(ReservedInstanceId=missing_id)
    )
    assert code == "ResourceNotFoundException", (
        f"DescribeReservedInstances: expected ResourceNotFoundException for a well-formed but "
        f"unknown id, got {code}"
    )
    assert message == "Reservation id not found", (
        f"DescribeReservedInstances: got message {message!r}"
    )

    missing_offering_id = str(uuid.uuid4())
    code, message = _error(
        lambda: os_client.describe_reserved_instance_offerings(
            ReservedInstanceOfferingId=missing_offering_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"DescribeReservedInstanceOfferings: expected ResourceNotFoundException for a well-formed "
        f"but unknown id, got {code}"
    )
    assert message == "Offering id not found", (
        f"DescribeReservedInstanceOfferings: got message {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
