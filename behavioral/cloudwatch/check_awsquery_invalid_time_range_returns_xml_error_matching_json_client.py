"""awsquery-invalid-time-range-returns-xml-error-matching-json-client."""
from __future__ import annotations

import datetime
import urllib.parse

import botocore.parsers
import botocore.serialize
import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "awsquery-invalid-time-range-returns-xml-error-matching-json-client"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricStatistics with StartTime after EndTime is rejected with the same Error.Code
    and Error.Message whether the request is sent over the awsQuery wire protocol or through
    boto3's JSON-protocol client -- one validation, carried faithfully by both.
    """
    cw = ctx.client("cloudwatch")
    assert cw.meta.service_model.resolved_protocol == "json", (
        f"boto3 resolved cloudwatch to {cw.meta.service_model.resolved_protocol!r}, "
        "expected 'json' -- the premise that the two calls below use different wire "
        "protocols does not hold"
    )
    namespace = ctx.unique_name("sim2real-behav-qerr-")
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    bad_range = {
        "Namespace": namespace,
        "MetricName": "M",
        "StartTime": now,
        "EndTime": now - datetime.timedelta(minutes=5),
        "Period": 60,
        "Statistics": ["Sum"],
    }

    # Positive control: the same request with StartTime before EndTime succeeds over awsQuery.
    good_range = {**bad_range, "StartTime": bad_range["EndTime"], "EndTime": bad_range["StartTime"]}
    status, parsed, raw = _query_call(cw, ctx.http_verify, "GetMetricStatistics", good_range)
    assert status == 200, (
        f"the positive control's awsQuery GetMetricStatistics returned HTTP {status}: {parsed!r}"
    )
    assert parsed.get("Label") == "M", f"the positive control's Label read as {parsed.get('Label')!r}"

    status, parsed, raw = _query_call(cw, ctx.http_verify, "GetMetricStatistics", bad_range)
    assert status == 400, f"awsQuery call returned HTTP {status}, expected 400: {parsed!r}"
    assert raw.lstrip().startswith(b"<ErrorResponse"), (
        f"awsQuery error body did not open with an <ErrorResponse> envelope: {raw[:200]!r}"
    )
    query_error = parsed["Error"]
    assert query_error["Code"] == "InvalidParameterValue", (
        f"awsQuery Error.Code was {query_error['Code']!r}, expected 'InvalidParameterValue'"
    )
    assert query_error["Message"] == (
        "The parameter StartTime must be less than the parameter EndTime."
    ), f"awsQuery Error.Message was {query_error['Message']!r}"

    try:
        cw.get_metric_statistics(**bad_range)
        raise AssertionError("the JSON-protocol client's GetMetricStatistics unexpectedly succeeded")
    except ClientError as exc:
        json_error = exc.response["Error"]

    assert json_error["Code"] == query_error["Code"], (
        f"the JSON client's Error.Code {json_error['Code']!r} does not match the awsQuery "
        f"wire's {query_error['Code']!r} -- the two protocols disagree on the error identity"
    )
    assert json_error["Message"] == query_error["Message"], (
        f"the JSON client's Error.Message {json_error['Message']!r} does not match the "
        f"awsQuery wire's {query_error['Message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
