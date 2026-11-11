"""deep-logs-3-logacct-metric-extraction-policy-enabled-status-rejected."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-logs-3-logacct-metric-extraction-policy-enabled-status-rejected"
GROUP = "account-policies"
SERVICES = ["logs"]

_PREFIX = "sim2real-behav-logacct-"
_STREAM = "app"
_METRIC = "Hits"
_VALUE = 3


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1", "resource:account-singleton:logs-account-policy",
)
def run(ctx) -> None:
    """PutAccountPolicy rejects a METRIC_EXTRACTION_POLICY with Status "Enabled" and persists
    nothing, so the group's EMF events still yield a datapoint; Status "Disabled" is accepted.
    """
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    namespace = "Sim2Real/Behav/" + ctx.unique_name("logacct-")

    group = ctx.unique_name(_PREFIX + "emfrej-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK[:200]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=_STREAM)

    policy = ctx.unique_name(_PREFIX + "mer-")
    selection = f'LogGroupName IN ["{group}"]'

    # "Disabled" is the only Status AWS accepts; the model types policyDocument as a string.
    try:
        logs.put_account_policy(
            policyName=policy,
            policyType="METRIC_EXTRACTION_POLICY",
            policyDocument=json.dumps({"EmbeddedMetricFormat": {"Status": "Enabled"}}),
            selectionCriteria=selection,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
    else:
        ctx.on_cleanup(
            lambda: logs.delete_account_policy(
                policyName=policy, policyType="METRIC_EXTRACTION_POLICY"
            )
        )
        raise AssertionError(
            "PutAccountPolicy ACCEPTED a METRIC_EXTRACTION_POLICY with Status 'Enabled'; real AWS "
            "rejects every Status but 'Disabled'"
        )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for Status 'Enabled', got {code!r}: {message!r}"
    )
    assert message == "Invalid json policy document", (
        f"expected the policy-document refusal for Status 'Enabled', got {message!r}"
    )
    assert _describe(logs, policy) == [], "the rejected policy is nevertheless described"

    # EMF extraction still works for the group; datapoints appear ~15 s after PutLogEvents.
    deadline = time.monotonic() + 180.0
    while True:
        resp = logs.put_log_events(
            logGroupName=group,
            logStreamName=_STREAM,
            logEvents=[{"timestamp": _now_ms(), "message": _emf(namespace)}],
        )
        assert not resp.get("rejectedLogEventsInfo"), f"PutLogEvents rejected: {resp!r}"
        time.sleep(5.0)
        maximum, count = _stats(cw, namespace)
        if count > 0:
            break
        assert time.monotonic() < deadline, (
            f"after the REJECTED policy, {group!r}'s EMF events produced no datapoint in "
            f"{namespace!r} within 180s -- the rejected document took effect"
        )
    assert maximum == _VALUE, f"EMF datapoint Maximum {maximum!r} != emitted {_VALUE}"

    # Positive control: the valid document, same name and scope, is accepted.
    put = logs.put_account_policy(
        policyName=policy,
        policyType="METRIC_EXTRACTION_POLICY",
        policyDocument=json.dumps({"EmbeddedMetricFormat": {"Status": "Disabled"}}),
        selectionCriteria=selection,
    )
    ctx.on_cleanup(
        lambda: logs.delete_account_policy(policyName=policy, policyType="METRIC_EXTRACTION_POLICY")
    )
    assert put["accountPolicy"]["policyName"] == policy, f"PutAccountPolicy echoed {put!r}"
    described = _describe(logs, policy)
    assert len(described) == 1 and described[0]["selectionCriteria"] == selection, (
        f"the accepted policy is not described exactly once with its scope: {described!r}"
    )
    assert json.loads(described[0]["policyDocument"]) == {
        "EmbeddedMetricFormat": {"Status": "Disabled"}
    }, f"described policyDocument {described[0]['policyDocument']!r}"


def _emf(namespace: str) -> str:
    return json.dumps(
        {
            "_aws": {
                "Timestamp": _now_ms(),
                "CloudWatchMetrics": [
                    {
                        "Namespace": namespace,
                        "Dimensions": [["Grp"]],
                        "Metrics": [{"Name": _METRIC, "Unit": "Count"}],
                    }
                ],
            },
            "Grp": "rej",
            _METRIC: _VALUE,
        }
    )


def _stats(cw, namespace: str) -> tuple[float, float]:
    now = dt.datetime.now(dt.timezone.utc)
    queries = [
        {
            "Id": stat.lower(),
            "MetricStat": {
                "Metric": {
                    "Namespace": namespace,
                    "MetricName": _METRIC,
                    "Dimensions": [{"Name": "Grp", "Value": "rej"}],
                },
                "Period": 60,
                "Stat": stat,
            },
        }
        for stat in ("Maximum", "SampleCount")
    ]
    r = cw.get_metric_data(
        MetricDataQueries=queries,
        StartTime=now - dt.timedelta(minutes=30),
        EndTime=now + dt.timedelta(minutes=2),
    )
    by_id = {q["Id"]: q["Values"] for q in r["MetricDataResults"]}
    return max(by_id["maximum"], default=0.0), sum(by_id["samplecount"])


def _describe(logs, policy: str) -> list:
    found = []
    token = None
    while True:
        kwargs = {"policyType": "METRIC_EXTRACTION_POLICY"}
        if token is not None:
            kwargs["nextToken"] = token
        page = logs.describe_account_policies(**kwargs)
        found.extend(p for p in page.get("accountPolicies", []) if p["policyName"] == policy)
        token = page.get("nextToken")
        if not token:
            return found


def _now_ms() -> int:
    return int(time.time() * 1000)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
