"""list-datasource-packages-max-results-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-datasource-packages-max-results-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """ListDatasourcePackages with any MaxResults fails with ValidationException "Max results must be null",
    while the call without it returns every package in one response with no NextToken."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    # Ensure all three known packages have a recorded state.
    all_packages = ["DETECTIVE_CORE", "EKS_AUDIT", "ASFF_SECURITYHUB_FINDING"]
    d.update_datasource_packages(GraphArn=arn, DatasourcePackages=all_packages)
    _poll_until(
        probe=lambda: set(d.list_datasource_packages(GraphArn=arn).get("DatasourcePackages", {})),
        predicate=lambda keys: keys == set(all_packages),
        timeout_s=60.0,
        interval_s=3.0,
    )

    code, message = _error(lambda: d.list_datasource_packages(GraphArn=arn, MaxResults=1))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Max results must be null", f"unexpected message: {message!r}"

    # Positive control: the un-paginated call still works and returns every known package.
    resp = d.list_datasource_packages(GraphArn=arn)
    assert set(resp.get("DatasourcePackages", {})) == set(all_packages), (
        f"expected all three known datasource packages, got {sorted(resp.get('DatasourcePackages', {}))!r}"
    )
    assert not resp.get("NextToken"), f"expected no NextToken for an un-paginated response, got {resp!r}"


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
