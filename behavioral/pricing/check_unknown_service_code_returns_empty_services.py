"""unknown-service-code-returns-empty-services."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "unknown-service-code-returns-empty-services"
GROUP = "content"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """The Price List Query API is only served from us-east-1, eu-central-1 and ap-south-1, so the
    client pins us-east-1; ctx.client() honours the region override on every target."""
    return ctx.client(
        "pricing", region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeServices with an unknown ServiceCode returns an empty Services list without an
    error, while a real service code returns exactly its own metadata."""
    pricing = _pricing_client(ctx)

    resp = pricing.describe_services(ServiceCode="NotARealPricingServiceXYZ123")
    assert resp["Services"] == [], resp["Services"]

    control = pricing.describe_services(ServiceCode="AmazonEC2")
    assert len(control["Services"]) == 1, control["Services"]
    assert control["Services"][0]["ServiceCode"] == "AmazonEC2", control["Services"][0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
