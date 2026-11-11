"""op-contract-describeInstanceTypeOfferings."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstanceTypeOfferings"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceTypeOfferings returns t3.micro as an offering in this region
    and rejects an unrecognized filter name with InvalidParameterValue."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_instance_type_offerings(
        LocationType="region",
        Filters=[{"Name": "instance-type", "Values": ["t3.micro"]}],
    )
    offerings = resp.get("InstanceTypeOfferings", [])
    assert len(offerings) == 1, f"expected exactly one offering, got {offerings}"
    assert offerings[0]["InstanceType"] == "t3.micro", (
        f"expected InstanceType t3.micro, got {offerings[0]['InstanceType']}"
    )
    assert offerings[0]["LocationType"] == "region", (
        f"expected LocationType region, got {offerings[0]['LocationType']}"
    )
    assert offerings[0]["Location"] == ctx.region, (
        f"expected Location {ctx.region}, got {offerings[0]['Location']}"
    )

    code, message = _error(
        lambda: ec2.describe_instance_type_offerings(
            Filters=[{"Name": "totally-bogus-filter-name", "Values": ["x"]}]
        )
    )
    assert code == "InvalidParameterValue", f"unexpected error code: {code}"
    assert message == (
        "The filter 'totally-bogus-filter-name' is invalid"
    ), f"unexpected InvalidParameterValue message: {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
