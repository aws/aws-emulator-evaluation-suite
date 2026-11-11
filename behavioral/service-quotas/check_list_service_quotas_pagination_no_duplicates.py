"""list-service-quotas-pagination-no-duplicates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-service-quotas-pagination-no-duplicates"
GROUP = "state"
SERVICES = ["service-quotas"]


def _walk(sq, max_results: int) -> tuple[list[str], int]:
    seen: list[str] = []
    pages = 0
    token = None
    for _ in range(500):
        kwargs = {"ServiceCode": "ec2", "MaxResults": max_results}
        if token:
            kwargs["NextToken"] = token
        resp = sq.list_service_quotas(**kwargs)
        quotas = resp["Quotas"]
        assert len(quotas) <= max_results, (
            f"page returned {len(quotas)} items, exceeding MaxResults={max_results}"
        )
        for q in quotas:
            seen.append(q["QuotaCode"])
        pages += 1
        token = resp.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError(
            f"ListServiceQuotas(MaxResults={max_results}) pagination did not terminate within 500 pages"
        )
    return seen, pages


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServiceQuotas for EC2, walked with MaxResults 10 and 100, takes more than one page each with
    no page over its size, and both walks yield the same duplicate-free set of at least 50 quotas."""
    sq = ctx.client("service-quotas")

    seen10, pages10 = _walk(sq, 10)
    seen100, pages100 = _walk(sq, 100)

    assert len(seen10) == len(set(seen10)), "duplicate QuotaCode returned across pages (MaxResults=10)"
    assert len(seen100) == len(set(seen100)), "duplicate QuotaCode returned across pages (MaxResults=100)"
    assert pages10 > 1, f"expected MaxResults=10 to force multiple pages, got {pages10}"
    assert pages100 > 1, f"expected MaxResults=100 to force multiple pages, got {pages100}"
    assert set(seen10) == set(seen100), (
        f"walking with MaxResults=10 ({len(set(seen10))} codes) diverged from walking with "
        f"MaxResults=100 ({len(set(seen100))} codes)"
    )
    assert len(seen10) >= 50, f"expected at least 50 EC2 quotas, got {len(seen10)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
