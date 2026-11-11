"""concurrency-update-vpc-endpoint-nonexistent-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "concurrency-update-vpc-endpoint-nonexistent-id-rejected"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateVpcEndpoint for a well-formed but unknown endpoint id fails with ResourceNotFoundException and
    its exact message, while ListVpcEndpoints answers with a VpcEndpointSummaryList.
    """
    opensearch = ctx.client("opensearch")
    bogus_id = "aos-" + ("0" * 20)

    code, message = _error_detail(
        lambda: opensearch.update_vpc_endpoint(
            VpcEndpointId=bogus_id,
            VpcOptions={"SubnetIds": ["subnet-00000000000000000"], "SecurityGroupIds": ["sg-00000000000000000"]},
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = "The VPC endpoint doesn't exist, or you don't have access to it."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: listing (a read-only, always-valid op) still works against the
    # same client/account, proving the API itself is reachable and functional.
    resp = opensearch.list_vpc_endpoints()
    assert "VpcEndpointSummaryList" in resp, f"expected VpcEndpointSummaryList key, got keys={sorted(resp.keys())}"


def _error_detail(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
