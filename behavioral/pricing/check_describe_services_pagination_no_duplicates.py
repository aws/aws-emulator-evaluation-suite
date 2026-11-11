"""describe-services-pagination-no-duplicates."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "describe-services-pagination-no-duplicates"
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
    """Paginating DescribeServices with NextToken never repeats a ServiceCode already
    seen on an earlier page."""
    pricing = _pricing_client(ctx)
    codes: list[str] = []
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 25}
        if token:
            kwargs["NextToken"] = token
        resp = pricing.describe_services(**kwargs)
        codes.extend(service["ServiceCode"] for service in resp["Services"])
        token = resp.get("NextToken")
        if not token:
            break
    assert len(codes) > 25, f"expected to traverse more than one page, got {len(codes)} codes"
    assert len(codes) == len(set(codes)), "duplicate ServiceCode returned across pages"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
