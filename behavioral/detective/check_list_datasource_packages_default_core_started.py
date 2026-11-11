"""list-datasource-packages-default-core-started."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-datasource-packages-default-core-started"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """A behavior graph administered by this account has DETECTIVE_CORE ingestion STARTED."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    def _probe():
        pkgs = d.list_datasource_packages(GraphArn=arn).get("DatasourcePackages", {})
        return pkgs.get("DETECTIVE_CORE", {}).get("DatasourcePackageIngestState")

    state = _poll_until(_probe, lambda s: s == "STARTED", timeout_s=30.0, interval_s=2.0)
    assert state == "STARTED", f"expected DETECTIVE_CORE to be STARTED, last saw {state!r}"


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


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
