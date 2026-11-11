"""update-datasource-packages-missing-mandatory-core-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-datasource-packages-missing-mandatory-core-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """UpdateDatasourcePackages requires the full desired package set on every call,
    including the mandatory DETECTIVE_CORE package. Omitting it is rejected, EKS_AUDIT is
    not started as a side effect, and the same request with DETECTIVE_CORE included works."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    before = d.list_datasource_packages(GraphArn=arn).get("DatasourcePackages", {})
    eks_before = before.get("EKS_AUDIT", {}).get("DatasourcePackageIngestState")

    code, message = _error(lambda: d.update_datasource_packages(GraphArn=arn, DatasourcePackages=["EKS_AUDIT"]))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "UpdateDatasourcePackages request missing mandatory datasource package(s): [DETECTIVE_CORE]"
    ), f"unexpected message: {message!r}"

    # effect absent: EKS_AUDIT ingest state is unchanged by the rejected call
    after_rejected = d.list_datasource_packages(GraphArn=arn).get("DatasourcePackages", {})
    eks_after_rejected = after_rejected.get("EKS_AUDIT", {}).get("DatasourcePackageIngestState")
    assert eks_after_rejected == eks_before, (
        f"expected EKS_AUDIT state unchanged ({eks_before!r}), got {eks_after_rejected!r}"
    )

    # positive control: the same desired package, submitted alongside the mandatory
    # DETECTIVE_CORE package, is accepted and drives EKS_AUDIT to STARTED.
    d.update_datasource_packages(GraphArn=arn, DatasourcePackages=["DETECTIVE_CORE", "EKS_AUDIT"])
    state = _poll_until(
        probe=lambda: d.list_datasource_packages(GraphArn=arn)
        .get("DatasourcePackages", {})
        .get("EKS_AUDIT", {})
        .get("DatasourcePackageIngestState"),
        predicate=lambda s: s == "STARTED",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert state == "STARTED", f"expected EKS_AUDIT to reach STARTED once DETECTIVE_CORE is included, got {state!r}"


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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
