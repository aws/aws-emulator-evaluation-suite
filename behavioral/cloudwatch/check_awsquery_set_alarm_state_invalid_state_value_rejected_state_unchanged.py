"""awsquery-set-alarm-state-invalid-state-value-rejected-state-unchanged."""
from __future__ import annotations

import urllib.parse

import botocore.parsers
import botocore.serialize
import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "awsquery-set-alarm-state-invalid-state-value-rejected-state-unchanged"
GROUP = "multi-protocol-wire-parity"
SERVICES = ["cloudwatch"]


def _query_call(cw, verify, op_name: str, params: dict, *, validate: bool = True):
    """POST ``params`` to ``op_name`` over the raw awsQuery wire protocol (form POST, Action=
    and Version=2010-08-01) with TLS verified as ``verify``
    (``ctx.http_verify``); return (status, parsed, raw_body). ``validate=False`` sends a
    value the client-side validator would reject locally, so the server's own answer is seen.
    """
    model = cw.meta.service_model
    op = model.operation_model(op_name)
    serializer = botocore.serialize.create_serializer("query", include_validation=validate)
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """SetAlarmState with a StateValue outside the OK/ALARM/INSUFFICIENT_DATA enum is rejected
    over the awsQuery wire protocol with the server's own validation error, and the alarm's
    state is left exactly as a positive control (a valid StateValue) set it.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-qstateneg-")
    alarm_name = ctx.unique_name("sim2real-behav-qstateneg-")

    cw.put_metric_alarm(
        AlarmName=alarm_name, Namespace=namespace, MetricName="Errors", Statistic="Sum",
        Period=60, EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # Positive control: a valid StateValue over the same wire protocol succeeds.
    status, parsed, raw = _query_call(cw, ctx.http_verify, "SetAlarmState", {
        "AlarmName": alarm_name, "StateValue": "OK", "StateReason": "control",
    })
    assert status == 200, f"the positive control's SetAlarmState returned HTTP {status}: {parsed!r}"
    control_state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert control_state["StateValue"] == "OK", (
        f"positive control left StateValue {control_state['StateValue']!r}, expected 'OK'"
    )

    status, parsed, raw = _query_call(
        cw, ctx.http_verify, "SetAlarmState",
        {"AlarmName": alarm_name, "StateValue": "BROKEN", "StateReason": "x"},
        validate=False,
    )
    assert status == 400, f"awsQuery SetAlarmState with an invalid enum returned HTTP {status}: {parsed!r}"
    query_error = parsed["Error"]
    assert query_error["Code"] == "ValidationError", (
        f"awsQuery Error.Code was {query_error['Code']!r}, expected 'ValidationError'"
    )
    assert query_error["Message"] == (
        "1 validation error detected: Value 'BROKEN' at 'stateValue' failed to satisfy "
        "constraint: Member must satisfy enum value set: [INSUFFICIENT_DATA, ALARM, OK]"
    ), f"awsQuery Error.Message was {query_error['Message']!r}"

    try:
        cw.set_alarm_state(AlarmName=alarm_name, StateValue="BROKEN", StateReason="x")
        raise AssertionError("the JSON-protocol client's SetAlarmState unexpectedly succeeded")
    except ClientError as exc:
        json_error = exc.response["Error"]
    assert json_error["Code"] == query_error["Code"], (
        f"the JSON client's Error.Code {json_error['Code']!r} does not match the awsQuery "
        f"wire's {query_error['Code']!r}"
    )
    assert json_error["Message"] == query_error["Message"], (
        f"the JSON client's Error.Message {json_error['Message']!r} does not match the "
        f"awsQuery wire's {query_error['Message']!r}"
    )

    # Effect absent: the alarm is still exactly where the positive control left it.
    final_state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert final_state["StateValue"] == "OK", (
        f"the rejected SetAlarmState left StateValue {final_state['StateValue']!r}, expected "
        "the positive control's 'OK' to survive untouched"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
