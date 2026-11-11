"""get-attribute-values-pagination-respects-max-results."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-attribute-values-pagination-respects-max-results"
GROUP = "pagination"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )



@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAttributeValues honors MaxResults per page and hands out a NextToken whose
    second page contains genuinely new values, not a repeat of the first page."""
    pricing = _pricing_client(ctx)
    first = pricing.get_attribute_values(ServiceCode="AmazonEC2", AttributeName="instanceType", MaxResults=10)
    first_values = [v["Value"] for v in first["AttributeValues"]]
    assert len(first_values) <= 10, f"expected at most MaxResults=10 values, got {len(first_values)}"
    token = first.get("NextToken")
    assert token, "expected instanceType to span more than one page of 10"

    second = pricing.get_attribute_values(
        ServiceCode="AmazonEC2", AttributeName="instanceType", MaxResults=10, NextToken=token
    )
    second_values = [v["Value"] for v in second["AttributeValues"]]
    assert second_values, "expected a non-empty second page"
    assert len(second_values) <= 10, f"expected at most MaxResults=10 values, got {len(second_values)}"
    assert set(first_values).isdisjoint(second_values), "second page repeated first-page values"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
