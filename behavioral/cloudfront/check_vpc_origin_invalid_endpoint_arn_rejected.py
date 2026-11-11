"""vpc-origin-invalid-endpoint-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-origin-invalid-endpoint-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcOrigin fails with InvalidArgument "The parameter VpcOriginEndpointConfig Arn Invalid Format." both for
    a malformed ARN and for a well-formed S3 bucket ARN (not an instance or load balancer), and ListVpcOrigins
    lists neither rejected name."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-vpco-bad-")

    expected_message = "The parameter VpcOriginEndpointConfig Arn Invalid Format."
    bad_arn = "not-an-arn-at-all"
    code = message = None
    try:
        cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": name,
                "Arn": bad_arn,
                "OriginProtocolPolicy": "https-only",
                "HTTPPort": 80,
                "HTTPSPort": 443,
            }
        )
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    assert code == "InvalidArgument", f"expected 400 InvalidArgument for a malformed ARN, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The forbidden effect did not happen: no VPC origin with this name exists.
    listing = cf.list_vpc_origins()
    names = [
        i["Name"]
        for i in listing.get("VpcOriginList", {}).get("Items", []) or []
    ]
    assert name not in names

    # A well-formed ARN of a resource type that can never be a VPC origin (an S3 bucket) is
    # refused with the same answer.
    wrong_type_arn = f"arn:aws:s3:::{ctx.unique_name('sim2real-not-a-vpc-origin-')}"
    name2 = ctx.unique_name("sim2real-vpco-bad2-")
    code2 = message2 = None
    try:
        cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": name2,
                "Arn": wrong_type_arn,
                "OriginProtocolPolicy": "https-only",
                "HTTPPort": 80,
                "HTTPSPort": 443,
            }
        )
    except ClientError as exc:
        code2, message2 = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    assert code2 == "InvalidArgument", f"expected 400 InvalidArgument for a wrong-type ARN, got {code2!r}"
    assert message2 == expected_message, f"expected message {expected_message!r}, got {message2!r}"

    # The forbidden effect did not happen here either: no VPC origin with this second name exists.
    listing2 = cf.list_vpc_origins()
    names2 = [
        i["Name"]
        for i in listing2.get("VpcOriginList", {}).get("Items", []) or []
    ]
    assert name2 not in names2, f"expected {name2!r} absent from VpcOriginList, found it present"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
