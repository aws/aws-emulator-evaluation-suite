"""awsquery-put-metric-data-then-json-get-metric-statistics-returns-sums."""
from __future__ import annotations

import datetime
import time
import urllib.parse

import botocore.parsers
import botocore.serialize
import urllib3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "awsquery-put-metric-data-then-json-get-metric-statistics-returns-sums"
GROUP = "multi-protocol-wire-parity"
SERVICES = ["cloudwatch"]

_DEADLINE_S = 180.0  # bound on how long a published datapoint takes to become queryable


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Three datapoints published in one PutMetricData sent over the awsQuery wire protocol
    sum to the value a JSON-protocol GetMetricStatistics reports for the same minute: one
    metric store behind both wire protocols.
    """
    cw = ctx.client("cloudwatch")
    assert cw.meta.service_model.resolved_protocol == "json", (
        f"boto3 resolved cloudwatch to {cw.meta.service_model.resolved_protocol!r}, "
        "expected 'json' -- the premise that GetMetricStatistics below reads over a "
        "different wire protocol than the awsQuery write does not hold"
    )
    namespace = ctx.unique_name("sim2real-behav-qsum-")
    dims = [{"Name": "writer", "Value": "awsquery"}]
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, second=0)

    status, parsed, raw = _query_call(cw, ctx.http_verify, "PutMetricData", {
        "Namespace": namespace,
        "MetricData": [
            {"MetricName": "Requests", "Dimensions": dims, "Timestamp": now, "Value": 4.0, "Unit": "Count"},
            {"MetricName": "Requests", "Dimensions": dims, "Timestamp": now, "Value": 5.0, "Unit": "Count"},
            {"MetricName": "Requests", "Dimensions": dims, "Timestamp": now, "Value": 6.0, "Unit": "Count"},
        ],
    })
    assert status == 200, f"awsQuery PutMetricData returned HTTP {status}: {parsed!r}"
    assert raw.lstrip().startswith(b"<PutMetricDataResponse"), (
        f"awsQuery response did not open with a <PutMetricDataResponse> envelope: {raw[:200]!r}"
    )

    deadline = time.monotonic() + _DEADLINE_S
    points = []
    while time.monotonic() < deadline:
        points = cw.get_metric_statistics(
            Namespace=namespace, MetricName="Requests", Dimensions=dims,
            StartTime=now - datetime.timedelta(minutes=5), EndTime=now + datetime.timedelta(minutes=5),
            Period=60, Statistics=["Sum", "SampleCount", "Maximum", "Minimum"],
        )["Datapoints"]
        # Poll to the fully aggregated minute: an early read may hold only part of the batch.
        if len(points) == 1 and points[0]["SampleCount"] == 3.0:
            break
        time.sleep(2)
    assert len(points) == 1, (
        f"GetMetricStatistics (json protocol) saw {len(points)} datapoint(s) within "
        f"{_DEADLINE_S}s for a write sent over awsQuery: {points!r}"
    )
    point = points[0]
    assert point["Sum"] == 15.0, f"Sum read as {point['Sum']!r}, expected 4+5+6=15.0"
    assert point["SampleCount"] == 3.0, f"SampleCount read as {point['SampleCount']!r}, expected 3"
    assert point["Maximum"] == 6.0, f"Maximum read as {point['Maximum']!r}, expected 6.0"
    assert point["Minimum"] == 4.0, f"Minimum read as {point['Minimum']!r}, expected 4.0"
    assert point["Unit"] == "Count", f"Unit read as {point['Unit']!r}, expected 'Count'"
    assert point["Timestamp"].astimezone(datetime.timezone.utc).replace(tzinfo=None) == now.replace(tzinfo=None), (
        f"Timestamp bucketed as {point['Timestamp']!r}, expected the published minute {now!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
