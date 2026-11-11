"""update-datasource-packages-starts-ingestion."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-datasource-packages-starts-ingestion"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """After UpdateDatasourcePackages enables EKS_AUDIT (together with the mandatory DETECTIVE_CORE),
    ListDatasourcePackages reports its ingest state STARTED, where omitting it leaves it not STARTED."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    # Baseline: omitting EKS_AUDIT from the desired set stops it, so an EKS_AUDIT already
    # STARTED on the graph cannot make the transition below vacuous.
    d.update_datasource_packages(GraphArn=arn, DatasourcePackages=["DETECTIVE_CORE"])
    before = _poll_until(
        probe=lambda: _ingest_state(d, arn, "EKS_AUDIT"),
        predicate=lambda s: s != "STARTED",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert before != "STARTED", f"expected EKS_AUDIT not STARTED after omitting it, last saw {before!r}"

    d.update_datasource_packages(GraphArn=arn, DatasourcePackages=["DETECTIVE_CORE", "EKS_AUDIT"])

    state = _poll_until(
        probe=lambda: _ingest_state(d, arn, "EKS_AUDIT"),
        predicate=lambda s: s == "STARTED",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert state == "STARTED", f"expected EKS_AUDIT to reach STARTED, last saw {state!r}"


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _ingest_state(d, graph_arn: str, package: str):
    resp = d.list_datasource_packages(GraphArn=graph_arn)
    packages = resp.get("DatasourcePackages", {})
    detail = packages.get(package)
    return detail.get("DatasourcePackageIngestState") if detail else None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
