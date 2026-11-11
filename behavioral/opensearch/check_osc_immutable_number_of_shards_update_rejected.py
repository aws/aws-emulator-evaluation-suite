"""osc-immutable-number-of-shards-update-rejected."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "osc-immutable-number-of-shards-update-rejected"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== plumbing =====

ENGINE_VERSION = "OpenSearch_2.11"
# Two t3.small.search data nodes, no dedicated cluster manager nodes, no zone awareness, minimum gp3 volume, public
# endpoint with HTTPS enforced. Domains bill per node-hour, so teardown is registered BEFORE create.
CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 2,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
ENDPOINT_OPTIONS = {"EnforceHTTPS": True, "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# An endpoint data-plane FAIL marker: a domain endpoint the target published and then failed to
# answer on is scored as a fidelity fail, never as an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created, raise on anything else so a
    leaked 24x7 cluster is visible in the run log."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource-based policy letting this account's principals use the data plane."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _create_domain(ctx, *, scenario: str) -> str:
    """Create the two-node HTTPS-enforced domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(CLUSTER_CONFIG),
        EBSOptions=dict(EBS_OPTIONS),
        DomainEndpointOptions=dict(ENDPOINT_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    # CreateDomain is aggressively rate limited per account: jitter, then back off on throttling.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * (1 + attempt) + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1350.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(20.0)  # fixed-wait: domain creation converges over minutes, not a time semantic
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's own credentials for this account, never boto3's ambient chain, and sends with
    stdlib urllib so no third-party HTTP client is needed.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    if raw is not None:
        data = raw if isinstance(raw, bytes) else raw.encode()
    elif body is not None:
        data = json.dumps(body).encode()
    else:
        data = None
    headers = {"Content-Type": content_type} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer at all
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """A published Endpoint does not mean the authorizer has the access policy yet; signed requests
    can 403 for a while. Poll a cheap GET until it clears."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(10.0)  # fixed-wait: authorizer propagation, not a time semantic
    raise AssertionError(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _bulk_load(ctx, base: str, index: str, docs) -> dict:
    """_bulk-index (id, source) pairs and assert the engine reported no per-item error."""
    lines = []
    for doc_id, source in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(source))
    status, body = _signed_request(ctx, "POST", f"{base}/_bulk", raw="\n".join(lines) + "\n",
                                   content_type="application/x-ndjson")
    assert status == 200, f"_bulk returned HTTP {status!r}: {body!r}"
    assert body.get("errors") is False, (
        f"_bulk reported per-item errors loading {index!r}: "
        f"{[i for i in body.get('items', []) if 'error' in i.get('index', {})]!r}"
    )
    return body


def _index_health(ctx, base: str, index: str, query: str, *, want, timeout_s: float = 300.0) -> dict:
    """Poll index-scoped _cluster/health with an engine-side wait until ``want(health)`` holds.

    Index-scoped so the managed domain's own system indices cannot move the counts. Bounded by the
    engine's ``timeout`` inside a bounded outer loop, so a target that never settles fails, not hangs.
    """
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        status, last = _signed_request(ctx, "GET", f"{base}/_cluster/health/{index}?{query}&timeout=30s")
        if status == 200 and want(last):
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"index {index!r} health never satisfied the condition within {timeout_s}s "
        f"(query {query!r}, last health {last!r})",
    )


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end plumbing =====

_SCENARIO = "osc-immutable-shards"
_INDEX = "sim2real-immutable"
_DOCS = [(f"doc-{i}", {"n": i}) for i in range(4)]


def _index_settings(ctx, base: str) -> tuple:
    status, body = _signed_request(ctx, "GET", f"{base}/{_INDEX}/_settings/index.number_of_*")
    assert status == 200, f"GET _settings returned HTTP {status!r}: {body!r}"
    idx = body.get(_INDEX, {}).get("settings", {}).get("index", {})
    return idx.get("number_of_shards"), idx.get("number_of_replicas")


def _assert_rejected(status, body, *, expect_reason: str, label: str) -> None:
    err = body.get("error") if isinstance(body, dict) else None
    assert status == 400, f"{label} returned HTTP {status!r}, expected 400: {body!r}"
    assert isinstance(err, dict) and err.get("type") == "illegal_argument_exception", (
        f"{label} was refused with error type {(err or {}).get('type')!r}, expected "
        f"illegal_argument_exception: {body!r}"
    )
    causes = err.get("root_cause") or [{}]
    assert causes[0].get("type") == "illegal_argument_exception", (
        f"{label} root_cause type is {causes[0].get('type')!r}, expected illegal_argument_exception: {body!r}"
    )
    assert expect_reason in str(err.get("reason")), (
        f"{label} reason is {err.get('reason')!r}, expected it to contain {expect_reason!r}"
    )


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """index.number_of_shards is fixed at creation. An OPEN index refuses to change it with 400
    illegal_argument_exception and a CLOSED index refuses it as FINAL; both refusals are atomic and
    leave number_of_replicas, which updates on both states, unaffected."""
    domain = _create_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    status, created = _signed_request(ctx, "PUT", f"{base}/{_INDEX}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 1}},
        "mappings": {"properties": {"n": {"type": "integer"}}}})
    assert status == 200, f"creating index {_INDEX!r} returned HTTP {status!r}: {created!r}"
    _index_health(ctx, base, _INDEX, "wait_for_status=green",
                  want=lambda h: h.get("timed_out") is False and h.get("status") == "green")
    _bulk_load(ctx, base, _INDEX, _DOCS)
    assert _index_settings(ctx, base) == ("1", "1"), (
        f"a freshly created 1-shard 1-replica index reports settings {_index_settings(ctx, base)!r}"
    )

    # --- open index: number_of_shards is not dynamic ---------------------------------------------
    open_reason = "Can't update non dynamic settings [[index.number_of_shards]] for open indices"
    status, body = _signed_request(ctx, "PUT", f"{base}/{_INDEX}/_settings",
                                   body={"index": {"number_of_shards": 2}})
    _assert_rejected(status, body, expect_reason=open_reason,
                     label="PUT _settings number_of_shards=2 on an open index")
    status, body = _signed_request(ctx, "PUT", f"{base}/{_INDEX}/_settings",
                                   body={"index": {"number_of_shards": 2, "number_of_replicas": 0}})
    _assert_rejected(status, body, expect_reason=open_reason,
                     label="PUT _settings number_of_shards=2 + number_of_replicas=0 on an open index")
    after = _index_settings(ctx, base)
    assert after == ("1", "1"), (
        f"after two refused updates the index reports (shards, replicas) {after!r}, expected "
        f"('1', '1') -- a refused settings request must apply nothing, including its legal half"
    )

    # --- positive control: a dynamic setting IS accepted -----------------------------------------
    status, body = _signed_request(ctx, "PUT", f"{base}/{_INDEX}/_settings",
                                   body={"index": {"number_of_replicas": 0}})
    assert status == 200 and body.get("acknowledged") is True, (
        f"PUT _settings number_of_replicas=0 on an open index returned HTTP {status!r}: {body!r}"
    )
    assert _index_settings(ctx, base) == ("1", "0"), (
        f"the accepted replica change reads back as {_index_settings(ctx, base)!r}, expected ('1', '0')"
    )

    # --- closed index: number_of_shards is FINAL -------------------------------------------------
    status, body = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_close")
    assert status == 200 and body.get("acknowledged") is True, (
        f"closing {_INDEX!r} returned HTTP {status!r}: {body!r}"
    )
    status, body = _signed_request(ctx, "PUT", f"{base}/{_INDEX}/_settings",
                                   body={"index": {"number_of_shards": 2}})
    _assert_rejected(status, body,
                     expect_reason=f"final {_INDEX} setting [index.number_of_shards], not updateable",
                     label="PUT _settings number_of_shards=2 on a closed index")
    status, body = _signed_request(ctx, "PUT", f"{base}/{_INDEX}/_settings",
                                   body={"index": {"number_of_replicas": 1}})
    assert status == 200 and body.get("acknowledged") is True, (
        f"PUT _settings number_of_replicas=1 on a closed index returned HTTP {status!r}: {body!r}"
    )

    # --- reopen: shard count unchanged, data intact ----------------------------------------------
    status, body = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_open")
    assert status == 200 and body.get("acknowledged") is True, (
        f"reopening {_INDEX!r} returned HTTP {status!r}: {body!r}"
    )
    green = _index_health(ctx, base, _INDEX, "wait_for_status=green",
                          want=lambda h: h.get("timed_out") is False and h.get("status") == "green")
    assert green.get("active_primary_shards") == 1 and green.get("active_shards") == 2, (
        f"the reopened index reports {green.get('active_primary_shards')!r} primaries and "
        f"{green.get('active_shards')!r} active shards, expected 1 and 2: {green!r}"
    )
    assert _index_settings(ctx, base) == ("1", "1"), (
        f"the reopened index reports settings {_index_settings(ctx, base)!r}, expected ('1', '1')"
    )
    status, count = _signed_request(ctx, "GET", f"{base}/{_INDEX}/_count")
    assert status == 200 and count.get("count") == len(_DOCS), (
        f"_count on the reopened index returned HTTP {status!r} {count!r}, expected {len(_DOCS)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
