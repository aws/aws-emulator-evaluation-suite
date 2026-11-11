"""test-metric-filter-space-delimited-extraction."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-metric-filter-space-delimited-extraction"
GROUP = 'metric-filters'
SERVICES = ['logs']


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TestMetricFilter applies the space-delimited grammar (positional extraction, arity, glob,
    numeric comparison, '...'); PutMetricFilter stores the same pattern verbatim and rejects the
    same malformed one with the same InvalidParameterException message.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html
    """
    svc = ctx.client("logs")

    apache = "10.0.0.1 alice 1750000000 GET 200 1024"
    apache_5xx = "10.0.0.2 bob 1750000001 POST 503 77"
    too_few = "10.0.0.3 carol 1750000002"

    full = "[ip, user, ts, request, status, bytes]"

    # --- 1. positional extraction, exact extractedValues, 1-based eventNumber.
    resp = svc.test_metric_filter(
        filterPattern=full, logEventMessages=[too_few, apache, apache_5xx]
    )
    matches = resp["matches"]
    assert len(matches) == 2, (
        f"{full} must match the two 6-token messages and NOT the 3-token one, got {matches!r}"
    )
    assert [m["eventNumber"] for m in matches] == [2, 3], (
        f"eventNumber must be the 1-based index into logEventMessages, got {matches!r}"
    )
    assert matches[0]["eventMessage"] == apache, matches[0]
    assert matches[0]["extractedValues"] == {
        "$ip": "10.0.0.1",
        "$user": "alice",
        "$ts": "1750000000",
        "$request": "GET",
        "$status": "200",
        "$bytes": "1024",
    }, f"unexpected extractedValues: {matches[0]['extractedValues']!r}"

    # --- 2. a glob constraint inside the bracket list narrows the match set.
    glob_pattern = "[ip, user, ts, request, status=5*, bytes]"
    glob_resp = svc.test_metric_filter(
        filterPattern=glob_pattern, logEventMessages=[apache, apache_5xx]
    )
    glob_msgs = [m["eventMessage"] for m in glob_resp["matches"]]
    assert glob_msgs == [apache_5xx], (
        f"{glob_pattern} must match only the 503 line, got {glob_msgs!r}"
    )

    # --- 3. a numeric comparison inside the bracket list.
    num_pattern = "[ip, user, ts, request, status >= 400, bytes]"
    num_resp = svc.test_metric_filter(
        filterPattern=num_pattern, logEventMessages=[apache, apache_5xx]
    )
    num_msgs = [m["eventMessage"] for m in num_resp["matches"]]
    assert num_msgs == [apache_5xx], (
        f"{num_pattern} must compare numerically and match only the 503 line, got {num_msgs!r}"
    )

    # --- 4. '...' is a variable-length wildcard, so arity is not fixed.
    ellipsis_pattern = "[..., bytes]"
    ell_resp = svc.test_metric_filter(
        filterPattern=ellipsis_pattern, logEventMessages=[too_few, apache]
    )
    ell_msgs = {m["eventMessage"] for m in ell_resp["matches"]}
    assert ell_msgs == {too_few, apache}, (
        f"{ellipsis_pattern} must match messages of differing arity, got {sorted(ell_msgs)!r}"
    )
    ell_first = next(m for m in ell_resp["matches"] if m["eventMessage"] == apache)
    assert ell_first["extractedValues"].get("$bytes") == "1024", (
        f"'...' must still bind the trailing named field, got {ell_first['extractedValues']!r}"
    )

    # --- 5. no match at all -> an empty matches list, never a pass-through.
    none_resp = svc.test_metric_filter(
        filterPattern="[a, b, c, d, e, f, g, h, i, j]", logEventMessages=[apache, apache_5xx]
    )
    assert none_resp.get("matches", []) == [], (
        f"a pattern matching nothing must return matches=[], got {none_resp!r}"
    )

    # --- 6. consistency: the same grammar governs PutMetricFilter.
    group = ctx.unique_name("sim2real-behav-lg-tmf-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    filter_name = ctx.unique_name("sim2real-behav-mf-")
    svc.put_metric_filter(
        logGroupName=group,
        filterName=filter_name,
        filterPattern=num_pattern,
        metricTransformations=[
            {
                "metricName": "ErrorBytes",
                "metricNamespace": ctx.unique_name("sim2real-behav-mf-ns-"),
                "metricValue": "$bytes",
                "defaultValue": 0.0,
            }
        ],
    )
    described = svc.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name)
    stored = [f for f in described.get("metricFilters", []) if f["filterName"] == filter_name]
    assert len(stored) == 1, f"metric filter not found after PutMetricFilter: {described!r}"
    assert stored[0]["filterPattern"] == num_pattern, (
        "PutMetricFilter must store the filterPattern verbatim, got "
        f"{stored[0]['filterPattern']!r} for {num_pattern!r}"
    )

    # --- 7. and the same grammar ERRORS are shared: a pattern TestMetricFilter
    # rejects must be rejected by PutMetricFilter too, with no filter created.
    bad_pattern = "[ip, user, ts"
    test_code, test_message = _client_error(
        lambda: svc.test_metric_filter(filterPattern=bad_pattern, logEventMessages=[apache])
    )
    assert test_code == "InvalidParameterException", (
        f"TestMetricFilter must reject the unterminated pattern {bad_pattern!r}, got {test_code!r}"
    )
    assert test_message == "If a filter pattern starts with '[' it must end with ']'", (
        f"unexpected TestMetricFilter message for {bad_pattern!r}: {test_message!r}"
    )
    bad_name = ctx.unique_name("sim2real-behav-mf-bad-")
    put_code, put_message = _client_error(
        lambda: svc.put_metric_filter(
            logGroupName=group,
            filterName=bad_name,
            filterPattern=bad_pattern,
            metricTransformations=[
                {"metricName": "X", "metricNamespace": "Y", "metricValue": "1"}
            ],
        )
    )
    assert put_code == "InvalidParameterException", (
        f"PutMetricFilter must reject the same unterminated pattern, got {put_code!r}"
    )
    assert put_message == "If a filter pattern starts with '[' it must end with ']'", (
        f"unexpected PutMetricFilter message for {bad_pattern!r}: {put_message!r}"
    )
    after = svc.describe_metric_filters(logGroupName=group, filterNamePrefix=bad_name)
    assert after.get("metricFilters", []) == [], (
        f"a rejected PutMetricFilter must not create a filter: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
