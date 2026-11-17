"""describe-instance-types-maxresults-above-the-maximum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-instance-types-maxresults-above-the-maximum-rejected"
GROUP = "reference-data"
SERVICES = ["ec2"]

_INVALID_MAX_RESULTS = (
    "InvalidMaxResults",
    "Value ( 101 ) for parameter maxResults is invalid. Expecting a value from ( 5 ) to  ( 100 ).",
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    actual_code, actual_message = _error(fn)
    assert actual_code == code, f"expected {code}, got {actual_code}: {actual_message!r}"
    assert actual_message == message, f"unexpected message for {code}: {actual_message!r}"


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceTypes rejects a MaxResults above the documented maximum of 100,
    while the maximum itself still returns a full page.
    """
    ec2 = ctx.client("ec2")

    control = ec2.describe_instance_types(MaxResults=100)
    control_types = control["InstanceTypes"]
    assert len(control_types) == 100, f"expected 100 items at the documented maximum, got {len(control_types)}"

    expect_error(lambda: ec2.describe_instance_types(MaxResults=101), *_INVALID_MAX_RESULTS)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
