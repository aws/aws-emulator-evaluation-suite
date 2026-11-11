"""describe-services-ec2-attribute-names-present."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "describe-services-ec2-attribute-names-present"
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
    """DescribeServices scoped to AmazonEC2 returns exactly that service's metadata,
    including the well-known EC2 pricing attribute names."""
    pricing = _pricing_client(ctx)
    resp = pricing.describe_services(ServiceCode="AmazonEC2")
    assert len(resp["Services"]) == 1
    service = resp["Services"][0]
    assert service["ServiceCode"] == "AmazonEC2"
    attribute_names = set(service["AttributeNames"])
    expected = {"instanceType", "volumeType", "location", "operatingSystem", "tenancy"}
    assert expected.issubset(attribute_names), attribute_names - expected


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
