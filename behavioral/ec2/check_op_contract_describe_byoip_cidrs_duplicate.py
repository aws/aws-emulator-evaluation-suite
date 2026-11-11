"""op-contract-describe-byoip-cidrs-duplicate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-byoip-cidrs-duplicate"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeByoipCidrs lists BYOIP ranges and rejects a MaxResults outside [1, 100]."""
    ec2 = ctx.client("ec2")

    response = ec2.describe_byoip_cidrs(MaxResults=10)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert "ByoipCidrs" in response
    assert isinstance(response["ByoipCidrs"], list)

    try:
        ec2.describe_byoip_cidrs(MaxResults=101)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "InvalidMaxResults", (
            f"expected InvalidMaxResults for MaxResults=101, got {code!r}"
        )
        assert message == "The MaxResults parameter cannot be larger than 100.", (
            f"unexpected InvalidMaxResults message: {message!r}"
        )
    else:
        raise AssertionError(
            "expected a rejection for MaxResults=101 (valid range is 1-100), got 200"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
