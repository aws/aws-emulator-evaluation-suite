"""workload-insights-data-query-lifecycle."""
from __future__ import annotations

import re

import datetime as dt
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workload-insights-data-query-lifecycle"
GROUP = "query"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """StartQueryWorkloadInsightsTopContributorsData runs to SUCCEEDED and yields a datapoints list."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    target = {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": ctx.region}
    scope_id = _acquire_scope(ctx, nfm, target)["scopeId"]

    now = dt.datetime.now(dt.timezone.utc)
    started = nfm.start_query_workload_insights_top_contributors_data(
        scopeId=scope_id,
        startTime=now - dt.timedelta(hours=1),
        endTime=now,
        metricName="DATA_TRANSFERRED",
        destinationCategory="UNCLASSIFIED",
    )
    query_id = started["queryId"]
    assert query_id, f"expected a non-empty queryId, got {query_id!r}"

    final_status = _poll_until(
        lambda: nfm.get_query_status_workload_insights_top_contributors_data(scopeId=scope_id, queryId=query_id)[
            "status"
        ],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELED"),
        timeout_s=600.0,
        interval_s=5.0,
    )
    assert final_status == "SUCCEEDED", f"expected query {query_id} to reach SUCCEEDED, last status was {final_status!r}"

    results = nfm.get_query_results_workload_insights_top_contributors_data(scopeId=scope_id, queryId=query_id)
    datapoints = results["datapoints"]
    assert isinstance(datapoints, list), f"expected datapoints to be a list, got {type(datapoints).__name__}"
    assert results["unit"], f"expected a non-empty unit for metric DATA_TRANSFERRED, got {results['unit']!r}"
    for dp in datapoints:
        assert len(dp["timestamps"]) == len(dp["values"]), (
            f"datapoint {dp.get('label')!r} has {len(dp['timestamps'])} timestamps "
            f"but {len(dp['values'])} values"
        )
        assert dp["label"], f"expected a non-empty label on datapoint, got {dp['label']!r}"

    bogus_query_id = str(uuid.uuid4())
    try:
        nfm.get_query_results_workload_insights_top_contributors_data(scopeId=scope_id, queryId=bogus_query_id)
        raise AssertionError(f"expected ResourceNotFoundException for bogus queryId {bogus_query_id!r}, call succeeded")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = _without_request_suffix(err.response["Error"].get("Message"))
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a bogus queryId, got {code!r}"
        assert message == f"There's no query with id {{{bogus_query_id}}}", (
            f"expected the unknown-query message for {bogus_query_id}, got {message!r}"
        )


def _acquire_scope(ctx, nfm, target: dict) -> dict:
    """Acquire a scope. NetworkFlowMonitor allows only one scope per account/Region, so if one
    already exists (created by another check) it is reused."""
    try:
        resp = nfm.create_scope(targets=[target], tags={"sim2real-check": CHECK})
        scope_id, scope_arn = resp["scopeId"], resp["scopeArn"]
        ctx.on_cleanup(lambda: _delete_scope_and_wait(nfm, scope_id))
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
            raise
        existing = nfm.list_scopes().get("scopes", [])
        assert existing, "ServiceQuotaExceededException but no existing scope found via ListScopes"
        scope_id = existing[0]["scopeId"]
        scope_arn = nfm.get_scope(scopeId=scope_id)["scopeArn"]
    _wait_scope_succeeded(nfm, scope_id)
    return {"scopeId": scope_id, "scopeArn": scope_arn}


def _delete_scope_and_wait(nfm, scope_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    try:
        nfm.delete_scope(scopeId=scope_id)
    except ClientError as err:
        if err.response["Error"]["Code"] in ("ResourceNotFoundException", "ConflictException", "ValidationException"):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = nfm.get_scope(scopeId=scope_id)["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "DEACTIVATED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"scope {scope_id} did not fully deactivate within {timeout_s}s")


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0) -> None:
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == "SUCCEEDED", f"expected scope {scope_id} to reach SUCCEEDED, last status was {final!r}"


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


_REQUEST_SUFFIX = re.compile(
    r" \(Service: [A-Za-z0-9]+, Status Code: \d+, Request ID: [0-9a-fA-F-]+\)"
    r"( \(SDK Attempt Count: \d+\))?$"
)


def _without_request_suffix(message: str) -> str:
    """The message minus its per-request "(Service: ..., Request ID: ...) (SDK Attempt Count: n)"
    suffix, which is the only part that differs between calls."""
    return _REQUEST_SUFFIX.sub("", message or "")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

