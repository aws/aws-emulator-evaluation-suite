"""describe-instance-types-max-results-below-the-floor-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-instance-types-max-results-below-the-floor-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_BELOW_FLOOR = (
    "InvalidMaxResults",
    "Value ( 1 ) for parameter maxResults is invalid. Expecting a value from ( 5 ) to  ( 100 ).",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceTypes, sent past client-side validation, refuses a MaxResults below the
    documented minimum of 5, while MaxResults=5 succeeds and returns exactly 5 instance types
    plus a NextToken.
    """
    ec2 = ctx.client("ec2")
    raw_ec2 = ctx.client("ec2", config=Config(parameter_validation=False))

    expect_error(lambda: raw_ec2.describe_instance_types(MaxResults=1), *_BELOW_FLOOR)

    page = ec2.describe_instance_types(MaxResults=5)
    types = page.get("InstanceTypes", [])
    assert len(types) == 5, f"MaxResults=5 is the documented minimum; expected exactly 5 instance types, got {len(types)}"
    assert page.get("NextToken"), f"expected a NextToken past a full page of 5, got {page.get('NextToken')!r}"


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
