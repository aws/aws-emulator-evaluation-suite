"""osq-deep-opensearch-2-async-delete-by-query-task-completes-with-exact-subset."""
from __future__ import annotations

import http.client
import json
import random
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "osq-deep-opensearch-2-async-delete-by-query-task-completes-with-exact-subset"
GROUP = "data-plane"
SERVICES = ["opensearch"]

# ===== self-contained helpers =====

ENGINE_VERSION = "OpenSearch_2.19"
# Smallest legal single-node topology: a domain bills per node-hour, so this provisions the cheapest
# legal cluster and registers teardown BEFORE the create call.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Marks a failure of the domain endpoint the target itself published, so it reads as the
# target's own fault rather than a connection problem on the caller's side.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource policy letting THIS account's principals use the data plane. The account comes from
    STS, never a literal, so the same check passes in any account."""
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


def _create_min_domain(ctx) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-osq-").lower()[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        # Tagged at creation so a tag-based cleanup can find it if teardown is interrupted.
        TagList=[{"Key": "sim2real", "Value": CHECK[:256]}],
    )
    # CreateDomain is rate limited per account: jitter, then a bounded back-off on throttling only.
    for attempt in range(10):
        if attempt == 0:
            time.sleep(random.uniform(0, 5.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError(f"CreateDomain for {domain_name} still throttled after 10 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1500.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')!r}, Endpoint={last.get('Endpoint')!r})",
    )


def _ssl_context(verify) -> ssl.SSLContext:
    """Trust exactly what ctx.http_verify names: False -> unverified, a path -> that CA bundle."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for the target account (not boto3's ambient chain):
    signing as the wrong principal makes the domain's account-scoped policy 403 the request.
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
    ssl_ctx = _ssl_context(ctx.http_verify)
    try:
        with urllib.request.urlopen(req, timeout=120, context=ssl_ctx) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        # An HTTP status is data the caller asserts on; a transport failure is not. The endpoint was
        # published by the target itself, so failing to answer on it is the target's failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 420.0) -> None:
    """Processing=False + an Endpoint does NOT mean the data-plane authorizer has the access policy
    yet; signed requests can 403 for a while. Poll a cheap GET until it clears."""
    deadline = time.monotonic() + timeout_s
    status, body = None, None
    while time.monotonic() < deadline:
        status, body = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            break
        time.sleep(2)
    assert status == 200, f"signed GET / on the domain endpoint returned {status!r}: {body!r}"


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}.

    Never returns a falsy sentinel for a success body: a 2xx has no 'error' and yields the literal
    '<no error>', which cannot be confused with an engine error type."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type"))
    return "<no error>"


def _total(result) -> int:
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]


# ===== end self-contained helpers =====

# Ten documents; six are in the deleted subset. The whole-index count is deliberately different from
# the subset size, so a target that deletes everything (or reports the index size) fails.
_DOCS = [(f"d{n}", {"kind": "purge" if n < 6 else "keep", "n": n}) for n in range(10)]
_PURGE = sorted(doc_id for doc_id, src in _DOCS if src["kind"] == "purge")
_KEEP = sorted(doc_id for doc_id, src in _DOCS if src["kind"] == "keep")
# Throttled to 1 document/second in batches of 2: the API GUARANTEES the task runs for roughly
# len(_PURGE) seconds, so the in-flight state is observable by design rather than by luck.
_SCROLL_SIZE = 2
_RPS = 1


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """`_delete_by_query?wait_for_completion=false` returns a task that is observed in flight before it
    completes, and the completed task deleted exactly the six matching documents of ten in
    `ceil(6 / scroll_size)` batches, leaving the four non-matching documents readable."""
    domain = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = ctx.unique_name("sim2real-osq-dbq-").lower()
    status, body = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"kind": {"type": "keyword"}, "n": {"type": "integer"}}}})
    assert status == 200 and body.get("acknowledged") is True, (
        f"creating index {index!r} returned HTTP {status!r}: {body!r}")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))

    lines = []
    for doc_id, source in _DOCS:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(source))
    status, body = _signed_request(ctx, "POST", f"{base}/_bulk?refresh=true",
                                   raw="\n".join(lines) + "\n", content_type="application/x-ndjson")
    assert status == 200 and body.get("errors") is False, f"_bulk returned HTTP {status!r}: {body!r}"
    status, counted = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200 and counted.get("count") == len(_DOCS), (
        f"expected {len(_DOCS)} documents before the delete, _count says {counted!r}")

    status, accepted = _signed_request(
        ctx, "POST",
        f"{base}/{index}/_delete_by_query?wait_for_completion=false&refresh=true"
        f"&scroll_size={_SCROLL_SIZE}&requests_per_second={_RPS}",
        body={"query": {"term": {"kind": "purge"}}})
    assert status == 200, f"async _delete_by_query returned HTTP {status!r}: {accepted!r}"
    task_id = accepted.get("task")
    assert isinstance(task_id, str) and ":" in task_id and set(accepted) == {"task"}, (
        f"wait_for_completion=false must return ONLY a '<node>:<id>' task handle, got {accepted!r}")

    observed = []          # (completed, status.deleted) per poll
    final: dict = {}
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        status, final = _signed_request(ctx, "GET", f"{base}/_tasks/{task_id}")
        assert status == 200, f"GET _tasks/{task_id} returned HTTP {status!r}: {final!r}"
        observed.append((final.get("completed"), final.get("task", {}).get("status", {}).get("deleted")))
        if final.get("completed") is True:
            break
        time.sleep(0.5)
    assert final.get("completed") is True, (
        f"task {task_id} did not complete within 180s; polls observed {observed!r}")

    running = [d for c, d in observed if c is False]
    assert running, (
        f"the task was throttled to {_RPS} doc/s over {len(_PURGE)} documents, so at least one poll "
        f"must observe completed=false before completion; polls observed {observed!r}")
    progress = [d for _, d in observed]
    assert progress == sorted(progress), f"status.deleted went backwards across polls: {progress!r}"

    task = final.get("task", {})
    assert task.get("action") == "indices:data/write/delete/byquery", (
        f"task action was {task.get('action')!r}, expected indices:data/write/delete/byquery")
    assert f"{task.get('node')}:{task.get('id')}" == task_id, (
        f"task reports node/id {task.get('node')!r}:{task.get('id')!r}, polled as {task_id!r}")
    response = final.get("response")
    assert isinstance(response, dict), f"a completed task must carry a response: {final!r}"
    assert response.get("deleted") == len(_PURGE), (
        f"response.deleted is {response.get('deleted')!r}, expected exactly {len(_PURGE)} -- the "
        f"matched subset, not the {len(_DOCS)}-document index: {response!r}")
    assert response.get("total") == len(_PURGE), f"response.total is {response.get('total')!r}"
    assert response.get("batches") == -(-len(_PURGE) // _SCROLL_SIZE), (
        f"response.batches is {response.get('batches')!r}, expected "
        f"{-(-len(_PURGE) // _SCROLL_SIZE)} for scroll_size={_SCROLL_SIZE}")
    assert response.get("failures") == [] and response.get("version_conflicts") == 0, (
        f"the delete reported failures/conflicts: {response!r}")
    assert response.get("requests_per_second") == float(_RPS), (
        f"response.requests_per_second is {response.get('requests_per_second')!r}")

    # TERMINAL READ through different operations: exactly the complement survives.
    status, counted = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200 and counted.get("count") == len(_KEEP), (
        f"after deleting {len(_PURGE)} of {len(_DOCS)}, _count says {counted!r}, expected {len(_KEEP)}")
    status, left = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                   body={"size": 20, "query": {"match_all": {}}})
    assert status == 200 and sorted(_hit_ids(left)) == _KEEP, (
        f"surviving ids are {sorted(_hit_ids(left)) if status == 200 else left!r}, expected {_KEEP!r}")
    status, gone = _signed_request(ctx, "GET", f"{base}/{index}/_doc/{_PURGE[0]}")
    assert status == 404 and gone.get("found") is False, (
        f"deleted document {_PURGE[0]!r} is still readable: HTTP {status!r} {gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
