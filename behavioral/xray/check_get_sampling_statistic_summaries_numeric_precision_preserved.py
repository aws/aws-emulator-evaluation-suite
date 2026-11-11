"""get-sampling-statistic-summaries-numeric-precision-preserved."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-sampling-statistic-summaries-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Large request/sampled/borrow counts reported through GetSamplingTargets are echoed back
    by GetSamplingStatisticSummaries with full integer precision, not truncated or coerced
    to a lossy float representation (e.g. via a 32-bit float or double-precision boundary)."""
    xray = ctx.client("xray")
    rule_name = ctx.unique_name("sim2real-xr-rule-")

    created = xray.create_sampling_rule(
        SamplingRule={
            "RuleName": rule_name,
            "ResourceARN": "*",
            "Priority": 9999,
            "FixedRate": 0.05,
            "ReservoirSize": 1,
            "ServiceName": rule_name,
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["SamplingRuleRecord"]["SamplingRule"]
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=rule_name))
    assert created["RuleName"] == rule_name, f"CreateSamplingRule echoed {created['RuleName']!r}, expected {rule_name!r}"

    client_id = os.urandom(12).hex()
    request_count = 16_777_217  # 2**24 + 1: not representable as a 32-bit float
    sampled_count = 123_457
    borrow_count = 42

    summary = _report_until_summary_matches(
        ctx, rule_name, client_id, request_count, sampled_count, borrow_count, timeout_s=120.0
    )
    if summary is None:
        raise AssertionError(
            "GetSamplingStatisticSummaries never surfaced an aggregated entry matching the "
            "repeatedly-reported values for the freshly created rule within the poll budget; "
            "AWS does not document the aggregation interval/latency (or whether the first report "
            "from a new ClientID establishes a zero baseline) for this endpoint, so a "
            "longer-lived probe is needed to close this gap."
        )
    got_request = summary["RequestCount"]
    got_sampled = summary["SampledCount"]
    got_borrow = summary["BorrowCount"]
    assert got_request == request_count, f"req {got_request}!={request_count}"
    assert got_sampled == sampled_count, f"sampled {got_sampled}!={sampled_count}"
    assert got_borrow == borrow_count, f"borrow {got_borrow}!={borrow_count}"
    assert isinstance(summary["RequestCount"], int), f"RequestCount coerced to {type(summary['RequestCount'])}, not int: {summary['RequestCount']!r}"
    assert isinstance(summary["SampledCount"], int), f"SampledCount coerced to {type(summary['SampledCount'])}, not int: {summary['SampledCount']!r}"
    assert isinstance(summary["BorrowCount"], int), f"BorrowCount coerced to {type(summary['BorrowCount'])}, not int: {summary['BorrowCount']!r}"


def _submit_statistics_with_retry(ctx, statistics_document: dict, timeout_s: float = 30.0) -> dict:
    xray = ctx.client("xray")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return xray.get_sampling_targets(SamplingStatisticsDocuments=[statistics_document])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException":
                raise
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"newly created sampling rule never became usable via GetSamplingTargets: {last_exc}")


def _find_summary(ctx, rule_name: str):
    xray = ctx.client("xray")
    paginator_kwargs: dict = {}
    while True:
        resp = xray.get_sampling_statistic_summaries(**paginator_kwargs)
        for summary in resp.get("SamplingStatisticSummaries", []):
            if summary.get("RuleName") == rule_name:
                return summary
        next_token = resp.get("NextToken")
        if not next_token:
            return None
        paginator_kwargs = {"NextToken": next_token}


def _report_until_summary_matches(
    ctx, rule_name: str, client_id: str, request_count: int, sampled_count: int, borrow_count: int,
    timeout_s: float = 120.0,
):
    """Some X-Ray sampling-statistics implementations treat a client's first report as an
    initial baseline (surfacing a zero-valued summary) and only reflect real numbers on a
    subsequent report from the same ClientID/RuleName pair. Re-report the same fixed values on
    a steady cadence and poll for a summary that reflects them exactly, rather than assuming the
    very first report is echoed immediately."""
    deadline = time.monotonic() + timeout_s
    last_summary = None
    while time.monotonic() < deadline:
        statistics_document = {
            "RuleName": rule_name,
            "ClientID": client_id,
            "Timestamp": time.time(),
            "RequestCount": request_count,
            "SampledCount": sampled_count,
            "BorrowCount": borrow_count,
        }
        targets_resp = _submit_statistics_with_retry(ctx, statistics_document, timeout_s=30.0)
        assert targets_resp.get("UnprocessedStatistics", []) == [], (
            f"a well-formed statistics document for an existing rule must be processed: {targets_resp!r}"
        )

        time.sleep(4.0)
        summary = _find_summary(ctx, rule_name)
        if summary is not None:
            last_summary = summary
            if summary.get("RequestCount") == request_count:
                return summary
        time.sleep(4.0)
    return last_summary


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

