"""describe-reserved-instances-offerings-unrecognized-filter-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-reserved-instances-offerings-unrecognized-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeReservedInstancesOfferings rejects an unrecognized filter name, and the
    identical call with that filter removed succeeds."""
    ec2 = ctx.client("ec2")
    bogus_filter_name = "not-a-real-filter-name"

    code, message = _error(
        lambda: ec2.describe_reserved_instances_offerings(
            Filters=[{"Name": bogus_filter_name, "Values": ["a1.large"]}],
            OfferingClass="standard",
            ProductDescription="Linux/UNIX",
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message}"
    expected_message = f"The filter '{bogus_filter_name}' is invalid"
    assert message == expected_message, f"unexpected message: {message!r}"

    # positive control: the identical call, with only the unrecognized filter removed,
    # succeeds on the same wiring.
    resp = ec2.describe_reserved_instances_offerings(
        Filters=[{"Name": "instance-type", "Values": ["a1.large"]}],
        OfferingClass="standard",
        ProductDescription="Linux/UNIX",
    )
    assert isinstance(resp["ReservedInstancesOfferings"], list), (
        f"expected a list, got {type(resp['ReservedInstancesOfferings'])!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
