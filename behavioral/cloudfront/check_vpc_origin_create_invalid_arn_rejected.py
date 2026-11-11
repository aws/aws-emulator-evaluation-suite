"""vpc-origin-create-invalid-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "vpc-origin-create-invalid-arn-rejected"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcOrigin rejects a malformed origin ARN with InvalidArgument and its exact message, and
    ListVpcOrigins lists no VPC origin under the rejected name."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-vpcorigin-bad-")[:64]

    endpoint_config = {
        "Name": name,
        "Arn": "not-a-valid-arn",
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "http-only",
    }
    code, message = _error_code(lambda: cf.create_vpc_origin(VpcOriginEndpointConfig=endpoint_config))
    assert code == "InvalidArgument", f"expected InvalidArgument for a malformed VPC origin Arn, got {code!r}"
    expected = "The parameter VpcOriginEndpointConfig Arn Invalid Format."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listing = cf.list_vpc_origins()
    names = [i["Name"] for i in listing.get("VpcOriginList", {}).get("Items", []) or []]
    assert name not in names, f"a VPC origin named {name!r} exists despite the rejected create"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"create_vpc_origin with a malformed Arn unexpectedly succeeded: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
