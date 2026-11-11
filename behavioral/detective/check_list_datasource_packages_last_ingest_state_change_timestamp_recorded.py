"""list-datasource-packages-last-ingest-state-change-timestamp-recorded."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "list-datasource-packages-last-ingest-state-change-timestamp-recorded"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """UpdateDatasourcePackages does not just flip a state string: ListDatasourcePackages
    records a real, recent LastIngestStateChange[STARTED].Timestamp for the transition."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    before_call = datetime.now(timezone.utc)
    d.update_datasource_packages(GraphArn=arn, DatasourcePackages=["DETECTIVE_CORE", "EKS_AUDIT"])

    detail = _poll_until(
        probe=lambda: _package_detail(d, arn, "EKS_AUDIT"),
        predicate=lambda det: det is not None and det.get("DatasourcePackageIngestState") == "STARTED",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert detail is not None, "expected an EKS_AUDIT datasource package detail"
    started_change = detail.get("LastIngestStateChange", {}).get("STARTED")
    assert started_change and "Timestamp" in started_change, f"missing STARTED timestamp: {detail!r}"

    ts = started_change["Timestamp"]
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert ts.tzinfo is not None, f"expected a timezone-aware STARTED timestamp, got {ts!r}"
    # The recorded transition timestamp must not be absurdly in the past (a hardcoded stub
    # value) nor in the future relative to when we issued the call.
    skew_s = (ts - before_call).total_seconds()
    assert -300.0 <= skew_s <= 300.0, f"LastIngestStateChange timestamp {ts!r} implausible vs call time {before_call!r}"


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


def _package_detail(d, graph_arn: str, package: str):
    resp = d.list_datasource_packages(GraphArn=graph_arn)
    return resp.get("DatasourcePackages", {}).get(package)


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
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
