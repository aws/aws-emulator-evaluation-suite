"""invalid-parameter-value-family."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-parameter-value-family"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

_VALID_DASHBOARD_BODY = json.dumps(
    {
        "widgets": [
            {
                "type": "text",
                "x": 0,
                "y": 0,
                "width": 6,
                "height": 3,
                "properties": {"markdown": "# behavioral test dashboard"},
            }
        ]
    }
)

_INSIGHT_RULE_DEFINITION = json.dumps(
    {
        "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
        "AggregateOn": "Count",
        "LogGroupNames": ["/aws/lambda/*"],
        "LogFormat": "JSON",
        "Contribution": {"Keys": ["$.requestId"], "Filters": []},
    }
)

def _err(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:cloudwatch-insight-rule-quota")
def run(ctx) -> None:
    """Malformed or out-of-range values are rejected with InvalidParameterValue and exact messages,
    each paired with the same call on the same live resource succeeding with a valid value.
    """
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]

    dash_name = ctx.unique_name("sim2real-behav-cwprobe-dash-")
    cw.put_dashboard(DashboardName=dash_name, DashboardBody=_VALID_DASHBOARD_BODY)
    ctx.on_cleanup(lambda _n=dash_name: cw.delete_dashboards(DashboardNames=[_n]))

    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    now = datetime.now(timezone.utc)
    cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": "Probe", "Value": 1.0}])

    rule_name = ctx.unique_name("sim2real-behav-cwprobe-rule-")
    cw.put_insight_rule(RuleName=rule_name, RuleDefinition=_INSIGHT_RULE_DEFINITION)
    ctx.on_cleanup(lambda _n=rule_name: cw.delete_insight_rules(RuleNames=[_n]))

    # DeleteDashboards on an absent name succeeds rather than raising InvalidParameterValue.
    bogus_dash = ctx.unique_name("sim2real-behav-cwprobe-dash-missing-")
    cw.delete_dashboards(DashboardNames=[bogus_dash])

    resp = cw.get_dashboard(DashboardName=dash_name)
    assert resp["DashboardName"] == dash_name, f"GetDashboard: expected the real dashboard back, got {resp}"

    # Disallowed characters, distinct from a validly-named absent dashboard.
    code, message = _err(lambda: cw.get_dashboard(DashboardName="bad dashboard name!"))
    assert code == "InvalidParameterValue", (
        f"GetDashboard: expected InvalidParameterValue for a malformed name, got {code}"
    )
    assert message == 'The value for field DashboardName contains invalid characters. It can only contain alphanumerics, dash (-) and underscore (_).\n', f"GetDashboard: unexpected message {message!r}"

    cw.get_metric_statistics(
        Namespace=namespace,
        MetricName="Probe",
        StartTime=now - timedelta(minutes=10),
        EndTime=now + timedelta(minutes=1),
        Period=60,
        Statistics=["Average"],
    )

    code, message = _err(lambda: cw.get_metric_statistics(
        Namespace=namespace,
        MetricName="AnyMetric",
        StartTime=now - timedelta(minutes=10),
        EndTime=now,
        Period=7,
        Statistics=["Average"],
    ))
    assert code == "InvalidParameterValue", (
        f"GetMetricStatistics: expected InvalidParameterValue for Period=7, got {code}"
    )
    assert message == 'The parameter Period must be a value in the set [1, 5, 10, 20, 30].', f"GetMetricStatistics: unexpected message {message!r}"

    cw.get_insight_rule_report(
        RuleName=rule_name, StartTime=now - timedelta(minutes=10), EndTime=now, Period=60
    )

    code, message = _err(lambda: cw.get_insight_rule_report(
        RuleName=rule_name, StartTime=now - timedelta(minutes=10), EndTime=now, Period=7
    ))
    assert code == "InvalidParameterValue", (
        f"GetInsightRuleReport: expected InvalidParameterValue for Period=7, got {code}"
    )
    assert message == 'INVALID_PERIOD: A Period must be a multiple of 60 seconds, from 60 to 86400.', f"GetInsightRuleReport: unexpected message {message!r}"

    # CloudWatch delete APIs succeed as a no-op for an absent resource.
    bogus_stream = ctx.unique_name("sim2real-behav-cwprobe-mstream-missing-")
    cw.delete_metric_stream(Name=bogus_stream)

    # For a nonexistent rule these ops report Failures rather than raising.
    resp = cw.disable_insight_rules(RuleNames=[rule_name])
    assert resp.get("Failures", []) == [], f"unexpected failure disabling a real rule: {resp}"
    resp = cw.enable_insight_rules(RuleNames=[rule_name])
    assert resp.get("Failures", []) == [], f"unexpected failure enabling a real rule: {resp}"

    def dash_listed():
        return cw.list_dashboards(DashboardNamePrefix=dash_name).get("DashboardEntries", [])

    entries = _poll_until(dash_listed, lambda e: len(e) > 0, timeout_s=30, interval_s=2)
    assert any(e["DashboardName"] == dash_name for e in entries), f"expected {dash_name} in ListDashboards"

    dash_arn = f"arn:aws:cloudwatch::{account}:dashboard/{dash_name}"
    cw.tag_resource(ResourceARN=dash_arn, Tags=[{"Key": "k", "Value": "v"}])
    tags = cw.list_tags_for_resource(ResourceARN=dash_arn).get("Tags", [])
    assert any(t["Key"] == "k" for t in tags), f"expected tag on dashboard via ListTagsForResource, got {tags}"

    rule_arn = f"arn:aws:cloudwatch:{ctx.region}:{account}:insight-rule/{rule_name}"
    resp = cw.list_managed_insight_rules(ResourceARN=rule_arn)
    assert "ManagedRules" in resp, f"expected ManagedRules field from ListManagedInsightRules, got {resp}"

    def metrics_listed():
        return cw.list_metrics(Namespace=namespace).get("Metrics", [])

    metrics = _poll_until(metrics_listed, lambda m: len(m) > 0, timeout_s=30, interval_s=2)
    assert any(m["MetricName"] == "Probe" for m in metrics), f"expected Probe metric in ListMetrics, got {metrics}"

    streams = cw.list_metric_streams().get("Entries", [])
    assert bogus_stream not in {e["Name"] for e in streams}, "a never-created stream must not be listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
