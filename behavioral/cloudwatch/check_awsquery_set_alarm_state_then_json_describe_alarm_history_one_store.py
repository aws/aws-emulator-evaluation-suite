"""awsquery-set-alarm-state-then-json-describe-alarm-history-one-store."""
from __future__ import annotations

import json
import time
import urllib.parse

import botocore.parsers
import botocore.serialize
import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "awsquery-set-alarm-state-then-json-describe-alarm-history-one-store"
GROUP = "multi-protocol-wire-parity"
SERVICES = ["cloudwatch"]

_DEADLINE_S = 120.0  # bound on how long a SetAlarmState transition takes to appear in history


def _query_call(cw, verify, op_name: str, params: dict):
    """POST ``params`` to ``op_name`` over the raw awsQuery wire protocol (form POST, Action=
    and Version=2010-08-01) with TLS verified as ``verify``
    (``ctx.http_verify``); return (status, parsed, raw_body)."""
    model = cw.meta.service_model
    op = model.operation_model(op_name)
    serializer = botocore.serialize.create_serializer("query")
    serialized = serializer.serialize_to_request(params, op)
    endpoint = cw.meta.endpoint_url.rstrip("/")
    url = endpoint + serialized["url_path"]
    body = urllib.parse.urlencode(serialized["body"]).encode("utf-8")
    raw_creds = cw._request_signer._credentials
    creds = raw_creds.get_frozen_credentials() if hasattr(raw_creds, "get_frozen_credentials") else raw_creds
    req = AWSRequest(method="POST", url=url, data=body, headers=dict(serialized["headers"]))
    SigV4Auth(creds, model.signing_name, cw.meta.region_name).add_auth(req)
    pool = urllib3.PoolManager(
        cert_reqs="CERT_NONE" if verify is False else "CERT_REQUIRED",
        **({"ca_certs": verify} if isinstance(verify, str) else {}),
    )
    resp = pool.request("POST", url, body=body, headers=dict(req.headers.items()), retries=False)
    http_response = {
        "status_code": resp.status,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "body": resp.data,
        "context": {},
    }
    parsed = botocore.parsers.create_parser("query").parse(http_response, op.output_shape)
    return resp.status, parsed, resp.data


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A SetAlarmState sent over the awsQuery wire protocol (a raw signed form POST with
    Action=SetAlarmState&Version=2010-08-01) is the transition a JSON-protocol
    DescribeAlarmHistory reads back, with the state reason carried unchanged across protocols.
    """
    cw = ctx.client("cloudwatch")
    assert cw.meta.service_model.resolved_protocol == "json", (
        f"boto3 resolved cloudwatch to {cw.meta.service_model.resolved_protocol!r}, "
        "expected 'json' -- the premise that DescribeAlarmHistory below reads over a "
        "different wire protocol than the awsQuery write does not hold"
    )
    namespace = ctx.unique_name("sim2real-behav-qstate-")
    alarm_name = ctx.unique_name("sim2real-behav-qstate-")

    cw.put_metric_alarm(
        AlarmName=alarm_name, Namespace=namespace, MetricName="Errors", Statistic="Sum",
        Period=60, EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    reason = f"sim2real awsQuery transition {alarm_name}"
    status, parsed, raw = _query_call(cw, ctx.http_verify, "SetAlarmState", {
        "AlarmName": alarm_name, "StateValue": "ALARM", "StateReason": reason,
    })
    assert status == 200, f"awsQuery SetAlarmState returned HTTP {status}: {parsed!r}"
    assert raw.lstrip().startswith(b"<SetAlarmStateResponse"), (
        f"awsQuery response did not open with a <SetAlarmStateResponse> envelope: {raw[:200]!r}"
    )

    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(described) == 1, f"DescribeAlarms returned {len(described)} alarms"
    assert described[0]["StateValue"] == "ALARM", (
        f"DescribeAlarms (json) read StateValue {described[0]['StateValue']!r} after an "
        "awsQuery SetAlarmState to ALARM"
    )
    assert described[0]["StateReason"] == reason, (
        f"DescribeAlarms (json) read StateReason {described[0]['StateReason']!r}, expected "
        f"{reason!r}"
    )

    # The alarm keeps evaluating, so later transitions may follow; select the one this check wrote.
    summary = "Alarm updated from INSUFFICIENT_DATA to ALARM"
    deadline = time.monotonic() + _DEADLINE_S
    items: list = []
    written: list = []
    while time.monotonic() < deadline:
        items = []
        for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=alarm_name, HistoryItemType="StateUpdate"
        ):
            items.extend(page["AlarmHistoryItems"])
        written = [i for i in items if i["HistorySummary"] == summary]
        if written:
            break
        time.sleep(2)
    assert len(written) == 1, (
        f"DescribeAlarmHistory (json protocol) held {len(written)} {summary!r} item(s) within "
        f"{_DEADLINE_S}s for one transition written over awsQuery; summaries were "
        f"{[i['HistorySummary'] for i in items]!r}"
    )
    new_state = json.loads(written[0]["HistoryData"])["newState"]
    assert new_state["stateValue"] == "ALARM", f"HistoryData newState.stateValue read as {new_state!r}"
    assert new_state["stateReason"] == reason, (
        f"HistoryData newState.stateReason read as {new_state.get('stateReason')!r}, expected the "
        f"awsQuery-written StateReason {reason!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
