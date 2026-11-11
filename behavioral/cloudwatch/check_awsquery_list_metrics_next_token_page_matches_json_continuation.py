"""awsquery-list-metrics-next-token-page-matches-json-continuation."""
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

CHECK = "awsquery-list-metrics-next-token-page-matches-json-continuation"
GROUP = "multi-protocol-wire-parity"
SERVICES = ["cloudwatch"]

_METRIC_COUNT = 501  # one over the documented 500-per-page cap, to force a NextToken
_PAGE_CAP = 500
_DISCOVERY_DEADLINE_S = 750.0  # metric catalog discovery (ListMetrics) is an AWS-defined period


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


@tags("axis:happy-path", "cap:c2", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """ListMetrics over the awsQuery wire protocol caps a page at 500 and mints a NextToken
    for the rest; a JSON-protocol client handed that same token continues the identical
    page, so one catalog paginates behind both wire protocols.
    """
    cw = ctx.client("cloudwatch")
    assert cw.meta.service_model.resolved_protocol == "json", (
        f"boto3 resolved cloudwatch to {cw.meta.service_model.resolved_protocol!r}, "
        "expected 'json' -- the premise that the continuation below crosses wire protocols "
        "does not hold"
    )
    namespace = ctx.unique_name("sim2real-behav-qpage-")
    names = [f"M{i:04d}" for i in range(_METRIC_COUNT)]
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0, second=0)

    status, parsed, raw = _query_call(cw, ctx.http_verify, "PutMetricData", {
        "Namespace": namespace,
        "MetricData": [{"MetricName": n, "Timestamp": now, "Value": 1.0, "Unit": "Count"} for n in names],
    })
    assert status == 200, f"awsQuery PutMetricData returned HTTP {status}: {parsed!r}"

    left = ctx.time_left()
    budget = _DISCOVERY_DEADLINE_S if left is None else min(_DISCOVERY_DEADLINE_S, left - 30.0)
    deadline = time.monotonic() + budget
    # Discovery converges over time: compare protocols only once page 1 plus its awsQuery
    # continuation together list exactly the published names, so both reads see one catalog.
    page1_names: list[str] = []
    awsquery_page2_names: set[str] = set()
    next_token = None
    while time.monotonic() < deadline:
        status, parsed, raw = _query_call(cw, ctx.http_verify, "ListMetrics", {"Namespace": namespace})
        assert status == 200, f"awsQuery ListMetrics returned HTTP {status}: {parsed!r}"
        page1_names = [m["MetricName"] for m in parsed.get("Metrics", [])]
        next_token = parsed.get("NextToken")
        if next_token:
            status, parsed, raw = _query_call(
                cw, ctx.http_verify, "ListMetrics", {"Namespace": namespace, "NextToken": next_token})
            assert status == 200, f"awsQuery ListMetrics continuation returned HTTP {status}: {parsed!r}"
            awsquery_page2_names = {m["MetricName"] for m in parsed.get("Metrics", [])}
            if set(page1_names) | awsquery_page2_names == set(names):
                break
        time.sleep(2)
    assert next_token and set(page1_names) | awsquery_page2_names == set(names), (
        f"ListMetrics (awsQuery) page 1 plus its continuation never listed the {_METRIC_COUNT} "
        f"published metrics within {_DISCOVERY_DEADLINE_S}s; saw {len(page1_names)} + "
        f"{len(awsquery_page2_names)} metric(s), NextToken={next_token!r}"
    )
    assert len(page1_names) == _PAGE_CAP, (
        f"ListMetrics (awsQuery) page 1 held {len(page1_names)} metrics while minting a "
        f"NextToken, expected exactly the documented {_PAGE_CAP}-item cap"
    )
    assert len(set(page1_names)) == len(page1_names), (
        "ListMetrics (awsQuery) page 1 repeated a metric name within one page"
    )
    assert not (awsquery_page2_names & set(page1_names)), (
        "the awsQuery NextToken continuation repeated a metric name already seen on page 1: "
        f"{sorted(awsquery_page2_names & set(page1_names))!r}"
    )

    json_page2 = cw.list_metrics(Namespace=namespace, NextToken=next_token)
    json_page2_names = {m["MetricName"] for m in json_page2["Metrics"]}
    assert json_page2_names == awsquery_page2_names, (
        "a JSON-protocol client handed the awsQuery-minted NextToken read a different "
        f"continuation: json saw {sorted(json_page2_names)!r}, awsQuery saw "
        f"{sorted(awsquery_page2_names)!r} -- the two protocols do not share one pagination "
        "cursor over one catalog"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
