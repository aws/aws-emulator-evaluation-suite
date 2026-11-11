"""document-optimistic-concurrency-version-conflict-rejected."""
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

CHECK = "document-optimistic-concurrency-version-conflict-rejected"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology (one t3.small.search data node, no dedicated cluster
# manager nodes, no zone awareness, minimum gp3 volume); teardown is registered BEFORE the
# create call.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
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


def _create_min_domain(ctx, *, access_policies=None, **overrides) -> str:
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between create and registration can never
    # leak a 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=(
            access_policies if access_policies is not None
            else _account_access_policy(ctx, domain_name)
        ),
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter before every attempt (larger
    # on the first, to desynchronize concurrent runs), then backoff on throttling — all inside the
    # bounded retry loop, never a bare wait.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * attempt + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1800.0) -> str:
    """Poll to Processing=False AND a published Endpoint on the same budget and interval for
    every target; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # Concurrent domain polls in one account hit DescribeDomain's rate limit: poll again.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name} never became searchable within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for THIS account (not boto3's ambient chain):
    signing as the wrong principal makes the domain's account-scoped policy 403 the request.
    Sends with stdlib urllib so no third-party HTTP client is needed.
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
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has
    the access policy yet; signed requests can 403 for a while. Poll a cheap GET until clear.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2)
    raise AssertionError(f"domain data plane still 403 after {timeout_s}s (last status {status})")


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


# ===== end shared domain helpers =====

_DOC_PATH = "_doc/counter"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """if_seq_no/if_primary_term implement optimistic concurrency: a stale sequence number is refused
    with version_conflict_engine_exception and leaves the document unchanged, while the current one
    succeeds and bumps _version.
    """
    domain = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-cas"
    # One shard, no replicas: _seq_no is per-shard, so a single shard makes the sequence
    # numbers under test unambiguous.
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"value": {"type": "integer"}}},
    })
    assert status in (200, 201), f"creating index failed with HTTP {status}: {created}"

    status, first = _signed_request(ctx, "PUT", f"{base}/{index}/{_DOC_PATH}", body={"value": 1})
    assert status == 201, f"initial index should return HTTP 201 (created), got {status}: {first}"
    assert first.get("_version") == 1, f"first write must be _version 1, got {first.get('_version')}"
    stale_seq_no = first.get("_seq_no")
    stale_primary_term = first.get("_primary_term")
    assert isinstance(stale_seq_no, int), f"_seq_no missing on the index response: {first}"
    assert isinstance(stale_primary_term, int), f"_primary_term missing: {first}"

    # Conditional write with the CURRENT sequence number succeeds and advances the version.
    status, second = _signed_request(
        ctx, "PUT",
        f"{base}/{index}/{_DOC_PATH}?if_seq_no={stale_seq_no}&if_primary_term={stale_primary_term}",
        body={"value": 2},
    )
    assert status == 200, f"conditional write with the current _seq_no failed ({status}): {second}"
    assert second.get("_version") == 2, (
        f"successful conditional write must bump _version to 2, got {second.get('_version')}"
    )
    current_seq_no = second.get("_seq_no")
    current_primary_term = second.get("_primary_term")
    assert current_seq_no > stale_seq_no, (
        f"_seq_no must advance after a write: {stale_seq_no} -> {current_seq_no}"
    )

    # Negative: replay the SAME conditional write with the now-stale sequence number.
    status, conflict = _signed_request(
        ctx, "PUT",
        f"{base}/{index}/{_DOC_PATH}?if_seq_no={stale_seq_no}&if_primary_term={stale_primary_term}",
        body={"value": 3},
    )
    assert status == 409, (
        f"a stale if_seq_no must be refused with HTTP 409, got {status}: {conflict}"
    )
    assert _error_type(conflict) == "version_conflict_engine_exception", (
        f"expected version_conflict_engine_exception, got {_error_type(conflict)!r}: {conflict}"
    )

    # Effect absent: the losing write did not modify the document.
    status, doc = _signed_request(ctx, "GET", f"{base}/{index}/{_DOC_PATH}")
    assert status == 200, f"document unreadable after the conflict ({status}): {doc}"
    assert doc.get("_source", {}).get("value") == 2, (
        f"refused write leaked through: value is {doc.get('_source', {}).get('value')}, expected 2"
    )
    assert doc.get("_version") == 2, (
        f"refused write bumped _version to {doc.get('_version')}, expected it to stay 2"
    )

    # Negative: a conditional DELETE with a stale sequence number is refused the same way,
    # and the document survives.
    status, del_conflict = _signed_request(
        ctx, "DELETE",
        f"{base}/{index}/{_DOC_PATH}?if_seq_no={stale_seq_no}&if_primary_term={stale_primary_term}",
    )
    assert status == 409, (
        f"conditional DELETE with a stale _seq_no must return HTTP 409, got {status}: {del_conflict}"
    )
    assert _error_type(del_conflict) == "version_conflict_engine_exception", (
        f"expected version_conflict_engine_exception on DELETE, got {_error_type(del_conflict)!r}"
    )
    status, still_there = _signed_request(ctx, "GET", f"{base}/{index}/{_DOC_PATH}")
    assert status == 200 and still_there.get("found") is True, (
        f"refused conditional DELETE removed the document: {status} {still_there}"
    )

    # Control: the same write pattern with the CURRENT sequence number still works.
    status, third = _signed_request(
        ctx, "PUT",
        f"{base}/{index}/{_DOC_PATH}"
        f"?if_seq_no={current_seq_no}&if_primary_term={current_primary_term}",
        body={"value": 4},
    )
    assert status == 200, f"control conditional write failed ({status}): {third}"
    assert third.get("_version") == 3, (
        f"control write must bump _version to 3, got {third.get('_version')}"
    )
    status, final = _signed_request(ctx, "GET", f"{base}/{index}/{_DOC_PATH}")
    assert final.get("_source", {}).get("value") == 4, (
        f"control write did not persist: {final.get('_source')}"
    )

    _signed_request(ctx, "DELETE", f"{base}/{index}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
