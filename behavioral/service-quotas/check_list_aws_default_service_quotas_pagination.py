"""list-aws-default-service-quotas-pagination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-aws-default-service-quotas-pagination"
GROUP = "state"
SERVICES = ["service-quotas"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAWSDefaultServiceQuotas for EC2 with MaxResults=10 takes more than one page, no page exceeds
    10 items, and the walk yields at least 50 QuotaCodes without duplicates."""
    sq = ctx.client("service-quotas")
    seen: list[str] = []
    page_sizes: list[int] = []
    token = None
    for _ in range(300):
        kwargs = {"ServiceCode": "ec2", "MaxResults": 10}
        if token:
            kwargs["NextToken"] = token
        resp = sq.list_aws_default_service_quotas(**kwargs)
        quotas = resp["Quotas"]
        page_sizes.append(len(quotas))
        for q in quotas:
            seen.append(q["QuotaCode"])
        token = resp.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError("ListAWSDefaultServiceQuotas pagination did not terminate within 300 pages")

    assert len(seen) == len(set(seen)), "duplicate QuotaCode returned across pages"
    assert len(seen) >= 50, f"expected at least 50 EC2 default quotas, got {len(seen)}"
    # A target that ignores MaxResults and dumps the whole catalog on page one would still
    # satisfy the two assertions above, defeating the point of this check: confirm the walk
    # actually required more than one round trip.
    assert len(page_sizes) > 1, (
        f"expected ListAWSDefaultServiceQuotas to require multiple MaxResults=10 pages for "
        f"{len(seen)} EC2 default quotas, got everything in {len(page_sizes)} page(s) -- "
        "MaxResults/NextToken pagination was never exercised"
    )
    for i, size in enumerate(page_sizes[:-1]):
        assert size <= 10, f"page {i} returned {size} quotas, exceeding the requested MaxResults=10"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
