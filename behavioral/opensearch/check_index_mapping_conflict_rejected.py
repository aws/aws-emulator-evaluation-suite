"""index-mapping-conflict-rejected."""
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

CHECK = "index-mapping-conflict-rejected"
GROUP = 'data-plane'
SERVICES = ['opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a
# real cost-leak class, so every check here provisions the cheapest legal cluster (one
# t3.small.search data node, no dedicated cluster manager nodes, no zone awareness, minimum gp3 volume)
# and registers teardown BEFORE the create call.
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
    # CreateDomain is aggressively rate limited per account: jitter, then backoff on throttling.
    time.sleep(random.uniform(0, 20.0))
    for attempt in range(12):
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _domain_status(osc, domain_name: str, deadline: float) -> dict:
    """DescribeDomain's DomainStatus, retried every 2 s on throttling until ``deadline``."""
    while True:
        try:
            return osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            if (exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2.0)


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1800.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = _domain_status(osc, domain_name, deadline)
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    raise AssertionError(
        f"domain {domain_name} never became searchable within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for the target account (not boto3's ambient chain):
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
        time.sleep(2.0)
    raise AssertionError(f"domain data plane still 403 after {timeout_s}s (last status {status})")


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _error_reason(payload) -> str:
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("reason") or "")
    return ""


def _mapped_type(ctx, base: str, index: str, field: str):
    status, mapping = _signed_request(ctx, "GET", f"{base}/{index}/_mapping")
    assert status == 200, f"_mapping read failed with HTTP {status}: {mapping}"
    props = mapping.get(index, {}).get("mappings", {}).get("properties", {})
    return props.get(field, {}).get("type")


# ===== end duplicated helpers =====


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A strict index mapping rejects an undeclared field and an incompatible field-type
    change, leaving the stored mapping and document set untouched, while an additive
    mapping change is still accepted.
    """
    domain = _create_min_domain(ctx)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-mapping"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {
            "dynamic": "strict",
            "properties": {"title": {"type": "keyword"}, "views": {"type": "integer"}},
        },
    })
    assert status in (200, 201), f"creating strict-mapped index failed with HTTP {status}: {created}"
    assert created.get("acknowledged") is True, f"index creation not acknowledged: {created}"

    # Control: a document that matches the declared mapping is accepted.
    status, ok = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/1", body={"title": "declared", "views": 1}
    )
    assert status in (200, 201), f"valid document rejected with HTTP {status}: {ok}"

    # Negative 1: exactly one undeclared field under dynamic:strict.
    status, strict = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/2",
        body={"title": "undeclared-field", "views": 2, "undeclared": "x"},
    )
    assert status == 400, f"strict mapping must reject an undeclared field, got HTTP {status}: {strict}"
    assert _error_type(strict) == "strict_dynamic_mapping_exception", (
        f"expected strict_dynamic_mapping_exception, got {_error_type(strict)!r}: {strict}"
    )
    assert "undeclared" in _error_reason(strict), (
        f"error must name the undeclared field, got {_error_reason(strict)!r}"
    )

    # Effect absent: the rejected document was not stored.
    status, refreshed = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh failed with HTTP {status}: {refreshed}"
    status, count = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"_count failed with HTTP {status}: {count}"
    assert count.get("count") == 1, (
        f"rejected document must not be stored, _count says {count.get('count')}"
    )
    status, missing = _signed_request(ctx, "GET", f"{base}/{index}/_doc/2")
    assert status == 404, f"rejected document exists, GET returned {status}: {missing}"

    # Negative 2: an incompatible type change on an existing field.
    status, conflict = _signed_request(
        ctx, "PUT", f"{base}/{index}/_mapping", body={"properties": {"title": {"type": "text"}}}
    )
    assert status == 400, (
        f"changing keyword->text on an existing field must be rejected, got HTTP {status}: {conflict}"
    )
    assert _error_type(conflict) == "illegal_argument_exception", (
        f"expected illegal_argument_exception, got {_error_type(conflict)!r}: {conflict}"
    )
    assert "title" in _error_reason(conflict), (
        f"error must name the conflicting field, got {_error_reason(conflict)!r}"
    )
    # Effect absent: the stored mapping still says keyword.
    assert _mapped_type(ctx, base, index, "title") == "keyword", (
        "field type was mutated by a rejected mapping change: title is now "
        f"{_mapped_type(ctx, base, index, 'title')!r}"
    )

    # Control: an ADDITIVE mapping change is legal, and the previously rejected document
    # becomes acceptable once its field is declared.
    status, added = _signed_request(
        ctx, "PUT", f"{base}/{index}/_mapping",
        body={"properties": {"undeclared": {"type": "keyword"}}},
    )
    assert status == 200, f"additive mapping change rejected with HTTP {status}: {added}"
    assert added.get("acknowledged") is True, f"mapping update not acknowledged: {added}"
    assert _mapped_type(ctx, base, index, "undeclared") == "keyword", (
        "additive mapping change did not persist the new field"
    )

    status, now_ok = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/2",
        body={"title": "undeclared-field", "views": 2, "undeclared": "x"},
    )
    assert status in (200, 201), (
        f"document should be accepted once its field is declared, got HTTP {status}: {now_ok}"
    )
    status, refreshed = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh failed with HTTP {status}: {refreshed}"
    status, count = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert count.get("count") == 2, (
        f"control document did not land after the additive mapping change: {count}"
    )

    # Cleanup as a free negative: the delete is asserted, and the deleted index is
    # confirmed gone via an independent read for the specific not-found error.
    status, deleted = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"deleting index failed with HTTP {status}: {deleted}"
    assert deleted.get("acknowledged") is True, f"index deletion not acknowledged: {deleted}"
    status, gone = _signed_request(ctx, "GET", f"{base}/{index}/_mapping")
    assert status == 404, f"deleted index still readable, GET _mapping returned {status}: {gone}"
    assert _error_type(gone) == "index_not_found_exception", (
        f"expected index_not_found_exception after delete, got {_error_type(gone)!r}: {gone}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
