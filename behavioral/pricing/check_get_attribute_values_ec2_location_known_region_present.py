"""get-attribute-values-ec2-location-known-region-present."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "get-attribute-values-ec2-location-known-region-present"
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
    """GetAttributeValues for AmazonEC2's location attribute enumerates real,
    human-readable AWS region names."""
    pricing = _pricing_client(ctx)
    values: set[str] = set()
    token = None
    for _ in range(5):
        kwargs = {"ServiceCode": "AmazonEC2", "AttributeName": "location", "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = pricing.get_attribute_values(**kwargs)
        values.update(v["Value"] for v in resp["AttributeValues"])
        token = resp.get("NextToken")
        if not token:
            break
    assert "US East (N. Virginia)" in values, (
        f"expected 'US East (N. Virginia)' among AmazonEC2 location values, got {sorted(values)}"
    )
    assert "Asia Pacific (Tokyo)" in values, (
        f"expected 'Asia Pacific (Tokyo)' among AmazonEC2 location values, got {sorted(values)}"
    )
    assert len(values) > 10, f"expected more than 10 AmazonEC2 location values, got {len(values)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
