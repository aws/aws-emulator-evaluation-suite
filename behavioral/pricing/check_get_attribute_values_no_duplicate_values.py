"""get-attribute-values-no-duplicate-values."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-attribute-values-no-duplicate-values"
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
    """GetAttributeValues for AmazonEC2 volumeType lists each value once in a page of 2-50 values,
    and the page contains the known EBS volume-type labels."""
    pricing = _pricing_client(ctx)
    resp = pricing.get_attribute_values(ServiceCode="AmazonEC2", AttributeName="volumeType", MaxResults=100)
    values = [v["Value"] for v in resp["AttributeValues"]]
    assert 2 <= len(values) <= 50, values
    assert len(values) == len(set(values)), "duplicate volumeType values in a single page"
    known_real_volume_types = {"General Purpose", "Provisioned IOPS", "Magnetic"}
    missing = known_real_volume_types - set(values)
    assert not missing, f"missing known real EBS volumeType labels: {missing}, got {values}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
