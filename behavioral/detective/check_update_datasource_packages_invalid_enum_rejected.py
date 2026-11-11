"""update-datasource-packages-invalid-enum-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-datasource-packages-invalid-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """UpdateDatasourcePackages with an unrecognized package fails with ValidationException and its exact
    message and the value never appears in ListDatasourcePackages, while EKS_AUDIT then reaches STARTED."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    code, message = _error(
        lambda: d.update_datasource_packages(
            GraphArn=arn, DatasourcePackages=["NOT_A_REAL_DATASOURCE_PACKAGE"]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "UpdateDatasourcePackages request includes unknown datasource package(s): "
        "[NOT_A_REAL_DATASOURCE_PACKAGE]"
    ), f"unexpected message: {message!r}"

    packages = d.list_datasource_packages(GraphArn=arn).get("DatasourcePackages", {})
    assert "NOT_A_REAL_DATASOURCE_PACKAGE" not in packages, f"unexpected packages: {packages!r}"

    # Positive control: a valid package value in the same shape of request succeeds.
    # UpdateDatasourcePackages requires the full desired package set to be specified on
    # every call, including the mandatory DETECTIVE_CORE package -- omitting it is itself
    # rejected with "missing mandatory datasource package(s): [DETECTIVE_CORE]".
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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
