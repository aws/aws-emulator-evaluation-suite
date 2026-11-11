"""awsquery-put-metric-alarm-then-json-describe-alarms-one-store."""
from __future__ import annotations

import urllib.parse

import botocore.parsers
import botocore.serialize
import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "awsquery-put-metric-alarm-then-json-describe-alarms-one-store"
GROUP = "multi-protocol-wire-parity"
SERVICES = ["cloudwatch"]


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PutMetricAlarm sent over the awsQuery wire protocol (a raw signed form POST with
    Action=PutMetricAlarm&Version=2010-08-01) is the same alarm a JSON-protocol DescribeAlarms
    reads back: one declared-state store behind both wire protocols.
    """
    cw = ctx.client("cloudwatch")
    assert cw.meta.service_model.resolved_protocol == "json", (
        f"boto3 resolved cloudwatch to {cw.meta.service_model.resolved_protocol!r}, "
        "expected 'json' -- the premise that DescribeAlarms below reads over a different "
        "wire protocol than the awsQuery write does not hold"
    )
    namespace = ctx.unique_name("sim2real-behav-qalarm-")
    alarm_name = ctx.unique_name("sim2real-behav-qalarm-")

    status, parsed, raw = _query_call(cw, ctx.http_verify, "PutMetricAlarm", {
        "AlarmName": alarm_name,
        "AlarmDescription": "sim2real awsQuery parity check",
        "Namespace": namespace,
        "MetricName": "Latency",
        "Statistic": "Average",
        "Period": 60,
        "EvaluationPeriods": 3,
        "Threshold": 42.5,
        "ComparisonOperator": "GreaterThanThreshold",
        "Dimensions": [{"Name": "writer", "Value": "awsquery"}],
    })
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    assert status == 200, f"awsQuery PutMetricAlarm returned HTTP {status}: {parsed!r}"
    assert raw.lstrip().startswith(b"<PutMetricAlarmResponse"), (
        f"awsQuery response did not open with a <PutMetricAlarmResponse> envelope: {raw[:200]!r}"
    )

    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(described) == 1, (
        f"DescribeAlarms (json protocol) returned {len(described)} alarm(s) for an alarm "
        f"written over awsQuery, expected 1: {described!r}"
    )
    alarm = described[0]
    assert alarm["AlarmDescription"] == "sim2real awsQuery parity check", (
        f"AlarmDescription read as {alarm['AlarmDescription']!r}"
    )
    assert alarm["Namespace"] == namespace, f"Namespace read as {alarm['Namespace']!r}"
    assert alarm["MetricName"] == "Latency", f"MetricName read as {alarm['MetricName']!r}"
    assert alarm["Statistic"] == "Average", f"Statistic read as {alarm['Statistic']!r}"
    assert alarm["Period"] == 60, f"Period read as {alarm['Period']!r}"
    assert alarm["EvaluationPeriods"] == 3, f"EvaluationPeriods read as {alarm['EvaluationPeriods']!r}"
    assert alarm["Threshold"] == 42.5, f"Threshold read as {alarm['Threshold']!r}"
    assert alarm["ComparisonOperator"] == "GreaterThanThreshold", (
        f"ComparisonOperator read as {alarm['ComparisonOperator']!r}"
    )
    assert alarm["Dimensions"] == [{"Name": "writer", "Value": "awsquery"}], (
        f"Dimensions read as {alarm['Dimensions']!r}"
    )

    # A second PutMetricAlarm sent over awsQuery, naming the same alarm but with a changed
    # ComparisonOperator, is a documented update-in-place: DescribeAlarms must read the new
    # value, never both or neither.
    status, parsed, raw = _query_call(cw, ctx.http_verify, "PutMetricAlarm", {
        "AlarmName": alarm_name,
        "AlarmDescription": "sim2real awsQuery parity check",
        "Namespace": namespace,
        "MetricName": "Latency",
        "Statistic": "Average",
        "Period": 60,
        "EvaluationPeriods": 3,
        "Threshold": 42.5,
        "ComparisonOperator": "LessThanThreshold",
        "Dimensions": [{"Name": "writer", "Value": "awsquery"}],
    })
    assert status == 200, f"awsQuery PutMetricAlarm (update) returned HTTP {status}: {parsed!r}"
    updated = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(updated) == 1, f"DescribeAlarms returned {len(updated)} alarms after the update"
    assert updated[0]["ComparisonOperator"] == "LessThanThreshold", (
        f"ComparisonOperator after the awsQuery update read as {updated[0]['ComparisonOperator']!r}, "
        "expected the update to replace it in place"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
