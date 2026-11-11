"""vpc-origin-invalid-arn-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return its botocore error code and message. A success raises: accepting input AWS refuses
    is a finding in itself, not an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected CreateVpcOrigin to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "vpc-origin-invalid-arn-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcOrigin with a syntactically invalid Arn fails with InvalidArgument and its exact message
    (CloudFront validates the ARN's shape before resolving it), and ListVpcOrigins lists no VPC origin
    under the rejected name."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-vpco-badarn-")
    code, message = _error_code(
        lambda: cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": name,
                "Arn": "not-a-valid-arn",
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
            }
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument for a malformed VPC origin Arn, got {code}"
    expected = "The parameter VpcOriginEndpointConfig Arn Invalid Format."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The forbidden effect did not happen: no VPC origin with this name exists.
    listing = cf.list_vpc_origins()
    names = [i["Name"] for i in listing.get("VpcOriginList", {}).get("Items", []) or []]
    assert name not in names, f"expected no VPC origin named {name!r} after a rejected create, found one"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
