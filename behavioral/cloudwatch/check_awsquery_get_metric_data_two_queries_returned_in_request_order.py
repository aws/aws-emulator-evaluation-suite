"""awsquery-get-metric-data-two-queries-returned-in-request-order."""
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

CHECK = "awsquery-get-metric-data-two-queries-returned-in-request-order"
GROUP = "multi-protocol-wire-parity"
SERVICES = ["cloudwatch"]

_DEADLINE_S = 120.0  # bound on how long a published datapoint takes to become queryable


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


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData over the awsQuery wire protocol returns MetricDataResults in the order
    the MetricDataQueries were submitted, not sorted by Id -- and a JSON-protocol client
    agrees on both the order and the values for the same two queries.
    """
    cw = ctx.client("cloudwatch")
    assert cw.meta.service_model.resolved_protocol == "json", (
        f"boto3 resolved cloudwatch to {cw.meta.service_model.resolved_protocol!r}, "
        "expected 'json' -- the premise that the comparison below crosses wire protocols "
        "does not hold"
    )
    namespace = ctx.unique_name("sim2real-behav-qorder-")
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, second=0)

    cw.put_metric_data(Namespace=namespace, MetricData=[
        {"MetricName": "Zeta", "Timestamp": now, "Value": 7.0, "Unit": "Count"},
        {"MetricName": "Alpha", "Timestamp": now, "Value": 3.0, "Unit": "Count"},
    ])

    def stat(metric: str):
        return {"Id": metric.lower(), "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": metric}, "Period": 60, "Stat": "Sum"}}

    # "zeta" sorts after "alpha" alphabetically, so an implementation that reorders by Id is
    # distinguishable from one that preserves submission order.
    query = {
        "MetricDataQueries": [stat("Zeta"), stat("Alpha")],
        "StartTime": now - datetime.timedelta(minutes=5),
        "EndTime": now + datetime.timedelta(minutes=5),
    }

    deadline = time.monotonic() + _DEADLINE_S
    status, parsed, raw = 0, {}, b""
    while time.monotonic() < deadline:
        status, parsed, raw = _query_call(cw, ctx.http_verify, "GetMetricData", query)
        results = parsed.get("MetricDataResults", [])
        if all(r.get("Values") for r in results):
            break
        time.sleep(2)

    assert status == 200, f"awsQuery GetMetricData returned HTTP {status}: {parsed!r}"
    results = parsed["MetricDataResults"]
    assert [r["Id"] for r in results] == ["zeta", "alpha"], (
        f"awsQuery GetMetricData returned ids in order {[r['Id'] for r in results]!r}, "
        "expected the submission order ['zeta', 'alpha']"
    )
    assert results[0]["Values"] == [7.0] and results[1]["Values"] == [3.0], (
        f"awsQuery GetMetricData values were {[r['Values'] for r in results]!r}, expected "
        "[[7.0], [3.0]]"
    )

    json_results = cw.get_metric_data(**query)["MetricDataResults"]
    assert [r["Id"] for r in json_results] == ["zeta", "alpha"], (
        f"the JSON-protocol GetMetricData returned ids in order "
        f"{[r['Id'] for r in json_results]!r}, expected ['zeta', 'alpha']"
    )
    assert [r["Values"] for r in json_results] == [[7.0], [3.0]], (
        f"the JSON-protocol GetMetricData values were {[r['Values'] for r in json_results]!r}, "
        "which disagrees with the awsQuery read of the same queries"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
