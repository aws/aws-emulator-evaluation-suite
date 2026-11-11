"""obs-opensearch-domain-metrics-listed-under-client-id-and-domain-name-only."""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "obs-opensearch-domain-metrics-listed-under-client-id-and-domain-name-only"
GROUP = 'metrics'
SERVICES = ['cloudwatch', 'opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}

NAMESPACE = "AWS/ES"
REQUIRED_METRICS = (
    "ClusterStatus.green", "ClusterStatus.yellow", "ClusterStatus.red",
    "Nodes", "SearchableDocuments",
)
POLL_DEADLINE_S = 600
#: How long a fresh domain's data-plane authorizer may take to admit the access policy.
DATA_PLANE_READY_S = 300.0
POLL_STEP_S = 2.0

# An endpoint data-plane FAIL marker: a check detail containing this string is classified as a
# real fidelity failure, ahead of a connection-error or not-implemented classification.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


# ===== helpers (self-contained) =====

def _signed(ctx, method: str, url: str, body: bytes | None = None,
            content_type: str = "application/json"):
    """Send a SigV4-signed ('es') HTTPS request to the domain endpoint; return (status, json).

    Signs with botocore and sends with stdlib urllib, so no third-party HTTP client is needed.
    Signs with the credentials ctx wired for the target account, never boto3's ambient chain:
    the domain's access policy is scoped to the caller account's root.
    """
    import urllib.error
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    headers = {"Content-Type": content_type} if body is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=body, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=body, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} {url} did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _delete_domain(osc, domain_name: str) -> None:
    """DeleteDomain, done when the domain is already gone."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _json_body(obj) -> bytes:
    return json.dumps(obj).encode()


def _access_policy(account_id: str, region: str, domain_name: str) -> str:
    arn = f"arn:aws:es:{region}:{account_id}:domain/{domain_name}"
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"{arn}/*",
        }],
    })


def _cap_s(ctx, timeout_s: float) -> float:
    """A wait's timeout bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))


def _not_graded(start: float, timeout_s: float, what: str) -> TimeoutError:
    """A wait the runner's budget cut short: no verdict."""
    return TimeoutError(
        f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
        f"{timeout_s:.0f}s wait for {what} ended; not graded"
    )


def _wait_domain_searchable(ctx, osc, domain_name: str, timeout_s: float = 1500) -> str:
    start = time.monotonic()
    cap_s = _cap_s(ctx, timeout_s)
    last = None
    while time.monotonic() - start < cap_s:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(POLL_STEP_S)
    if cap_s < timeout_s:
        raise _not_graded(start, timeout_s, f"domain {domain_name} to be searchable")
    detail = (f"domain {domain_name} never became searchable within {timeout_s}s "
              f"(last Processing={last.get('Processing') if last else '?'}, "
              f"Endpoint={last.get('Endpoint') if last else '?'})")
    raise AssertionError(detail)


def _health(ctx, base: str) -> dict:
    status, body = _signed(ctx, "GET", f"{base}/_cluster/health")
    assert status == 200, f"_cluster/health returned HTTP {status}: {body!r}"
    return body


def _wait_health(ctx, base: str, want: str, timeout_s: float = 120) -> dict:
    start = time.monotonic()
    cap_s = _cap_s(ctx, timeout_s)
    body = _health(ctx, base)
    while body.get("status") != want and time.monotonic() - start < cap_s:
        time.sleep(POLL_STEP_S)
        body = _health(ctx, base)
    if body.get("status") != want and cap_s < timeout_s:
        raise _not_graded(start, timeout_s, f"_cluster/health {want!r}")
    assert body.get("status") == want, (
        f"_cluster/health never reported {want!r} within {timeout_s}s; last body {body!r}"
    )
    return body


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:metrics", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A green single-node domain lists its ClusterStatus, Nodes and SearchableDocuments metrics in
    AWS/ES under exactly one dimension set, {ClientId, DomainName}, with Nodes at 1, and none in
    AWS/OpenSearchService.
    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-cloudwatchmetrics.html
    """
    osc = ctx.client("opensearch")
    cw = ctx.client("cloudwatch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Bounded startup jitter, not a wait for any condition: CreateDomain is throttled per account
    # and other suites provision domains too. No assertion below depends on this delay's length.
    time.sleep(random.uniform(0, 10.0))
    domain_name = ctx.unique_name("sim2real-xsvc-cwos-")[:28].rstrip("-")
    for attempt in range(12):
        try:
            osc.create_domain(
                DomainName=domain_name,
                EngineVersion=ENGINE_VERSION,
                ClusterConfig=dict(CLUSTER_CONFIG),
                EBSOptions=dict(EBS_OPTIONS),
                AccessPolicies=_access_policy(account_id, ctx.region, domain_name),
                TagList=[{"Key": "sim2real:managed", "Value": "true"},
                         {"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("CreateDomain still throttled after 12 attempts")
    ctx.on_cleanup(lambda: _delete_domain(osc, domain_name))

    endpoint = _wait_domain_searchable(ctx, osc, domain_name)
    base = ctx.endpoint_url(endpoint)
    # A published Endpoint does not mean the data-plane authorizer has the access policy yet.
    dp_start = time.monotonic()
    dp_cap_s = _cap_s(ctx, DATA_PLANE_READY_S)
    while True:
        st, body = _signed(ctx, "GET", f"{base}/")
        if st == 200 or time.monotonic() - dp_start >= dp_cap_s:
            break
        time.sleep(POLL_STEP_S)
    if st != 200 and dp_cap_s < DATA_PLANE_READY_S:
        raise _not_graded(dp_start, DATA_PLANE_READY_S, "the domain's data plane to answer")
    assert st == 200, f"signed GET / on the domain endpoint never returned 200: {st} {body!r}"

    # A replica-free index on the one node: the cluster reports green with that node before the
    # catalogue is read.
    index_a = ctx.unique_name("sim2real-health-")
    st, body = _signed(ctx, "PUT", f"{base}/{index_a}", _json_body(
        {"settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}}}))
    want_created = {"acknowledged": True, "shards_acknowledged": True, "index": index_a}
    assert (st, body) == (200, want_created), (
        f"PUT {index_a} with 0 replicas answered HTTP {st} {body!r}, expected 200 {want_created!r}"
    )
    green_body = _wait_health(ctx, base, "green")
    assert green_body.get("number_of_nodes") == 1, (
        f"_cluster/health number_of_nodes was {green_body.get('number_of_nodes')!r}, expected 1"
    )

    # The metric catalogue: AWS/ES, exactly {ClientId, DomainName}, nowhere else. ListMetrics
    # lists a domain metric once its first datapoint is in, so this polls to that condition.
    cat_start = time.monotonic()
    cat_cap_s = _cap_s(ctx, POLL_DEADLINE_S)
    while True:
        listed = []
        for page in cw.get_paginator("list_metrics").paginate(
                Namespace=NAMESPACE,
                Dimensions=[{"Name": "DomainName", "Value": domain_name}]):
            listed.extend(page["Metrics"])
        names_listed = {m["MetricName"] for m in listed}
        if set(REQUIRED_METRICS) <= names_listed or time.monotonic() - cat_start >= cat_cap_s:
            break
        time.sleep(POLL_STEP_S)
    missing = sorted(set(REQUIRED_METRICS) - names_listed)
    if missing and cat_cap_s < POLL_DEADLINE_S:
        raise _not_graded(cat_start, POLL_DEADLINE_S, "the AWS/ES metric catalogue")
    assert not missing, (
        f"ListMetrics({NAMESPACE}, DomainName={domain_name}) never listed {missing!r} within "
        f"{POLL_DEADLINE_S}s; listed {sorted(names_listed)!r}"
    )
    want_dims = {"ClientId": account_id, "DomainName": domain_name}
    for name in REQUIRED_METRICS:
        dim_sets = [{d["Name"]: d["Value"] for d in m["Dimensions"]}
                    for m in listed if m["MetricName"] == name]
        assert dim_sets == [want_dims], (
            f"{name} is listed with dimension sets {dim_sets!r}; expected exactly one, "
            f"{want_dims!r}"
        )
    # The listed Nodes series already holds a datapoint, and on a single-node domain its newest
    # one-minute Maximum is 1.
    now = datetime.now(timezone.utc)
    points = cw.get_metric_statistics(
        Namespace=NAMESPACE, MetricName="Nodes", Period=60, Statistics=["Maximum"],
        StartTime=now - timedelta(minutes=30), EndTime=now,
        Dimensions=[{"Name": k, "Value": v} for k, v in sorted(want_dims.items())],
    )["Datapoints"]
    assert points, f"GetMetricStatistics(Nodes) returned no datapoint for the listed {want_dims!r}"
    newest = max(points, key=lambda p: p["Timestamp"])
    assert newest["Maximum"] == 1.0, (
        f"the newest Nodes datapoint of a single-node domain is {newest!r}; expected Maximum 1.0"
    )
    other = []
    for page in cw.get_paginator("list_metrics").paginate(
            Namespace="AWS/OpenSearchService",
            Dimensions=[{"Name": "DomainName", "Value": domain_name}]):
        other.extend(page["Metrics"])
    assert other == [], (
        f"domain {domain_name} metrics appeared under AWS/OpenSearchService, which AWS does not "
        f"publish to: {[m['MetricName'] for m in other]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
