"""op-contract-describeCapacityReservationBillingRequests."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeCapacityReservationBillingRequests"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCapacityReservationBillingRequests with a valid Role answers 200 with a list field; an
    invalid Role value, which botocore does not validate, is rejected by the service with
    InvalidParameterValue and its exact message."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_capacity_reservation_billing_requests")

    # positive control: Role is a required parameter for this operation; a fresh account with no
    # billing-transfer requests still returns a well-formed 200 with a list-shaped billing-requests
    # field.
    response = ec2.describe_capacity_reservation_billing_requests(Role="odcr-owner")
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    data_fields = {k: v for k, v in response.items() if k not in ("ResponseMetadata", "NextToken")}
    assert data_fields, "expected at least one data field beyond ResponseMetadata/NextToken"
    field_name, field_value = next(iter(data_fields.items()))
    assert isinstance(field_value, list), f"expected {field_name!r} in the response body to be a list"

    # error boundary: an invalid Role value is never validated by botocore locally (it is a plain
    # string, not a locally-enforced enum), so this call reaches the service, which rejects it.
    code, message = _error(
        lambda: ec2.describe_capacity_reservation_billing_requests(Role="not-a-real-role")
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for an invalid Role value, got {code!r}"
    assert message == (
        "not-a-real-role is not a valid value for RoleType. "
        "Specify either odcr-owner or unused-reservation-billing-owner."
    ), f"unexpected InvalidParameterValue message {message!r}"


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
