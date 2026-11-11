"""concurrent-identical-reads-return-consistent-results."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-identical-reads-return-consistent-results"
GROUP = "concurrency"
SERVICES = ["pricing"]


def _pricing_client(ctx):
    """pricing is served in us-east-1 whatever the run's region; ctx.client's overrides pin the
    endpoint and the signing region on every target."""
    from botocore.config import Config

    return ctx.client(
        "pricing",
        region="us-east-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )



@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Firing the same read-only DescribeServices call from many threads concurrently
    must never produce cross-request corruption: every response reports the same
    AttributeNames set for the same ServiceCode."""
    pricing = _pricing_client(ctx)

    def _fetch(_):
        resp = pricing.describe_services(ServiceCode="AmazonEC2")
        service = resp["Services"][0]
        return service["ServiceCode"], tuple(sorted(service["AttributeNames"]))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_fetch, range(8)))

    assert len(results) == 8, f"expected 8 concurrent results, got {len(results)}"
    assert len(set(results)) == 1, f"expected identical results across concurrent reads, got {set(results)}"
    service_code, attribute_names = results[0]
    assert service_code == "AmazonEC2", f"expected ServiceCode AmazonEC2, got {service_code}"
    assert attribute_names, "expected a non-empty attribute set"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
