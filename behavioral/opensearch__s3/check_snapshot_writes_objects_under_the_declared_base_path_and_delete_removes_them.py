"""snapshot-writes-objects-under-the-declared-base-path-and-delete-removes-them."""
from __future__ import annotations

import http.client
import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "snapshot-writes-objects-under-the-declared-base-path-and-delete-removes-them"
GROUP = 'data-plane'
SERVICES = ['opensearch', 's3']

# The BlobStoreRepository layout under `base_path` -- a root-level blob whose basename starts with
# "index" (`index.latest` / `index-N`) plus an `indices/` subtree -- is AWS's documented repository
# format, not an API contract: the containment and byte-count assertions are the claim, and the
# names below are the ones AWS writes. `DELETE _snapshot/<repo>/<snap>` cleans
# up the repository's S3 data asynchronously, so the wait after it is a bounded poll that RAISES,
# never a sleep. A restore of the dead snapshot fails through a DIFFERENT exception than a plain GET
# of the same dead id: HTTP 500 `snapshot_restore_exception`, not the GET's HTTP 404
# `snapshot_missing_exception` -- the restore path wraps the lookup failure differently.
# `iam:PassRole` for `es.amazonaws.com` must be available to the credentials under test, and the
# 500/503 retry in `_register_repo` is the right wait for IAM propagation to that role.

# ===== plumbing shared with

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a real
# cost-leak class, so this provisions the cheapest legal cluster and registers teardown BEFORE create.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Prefixes a failure where a published domain endpoint did not answer, so it reads as a failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


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


def _create_min_domain(ctx, *, scenario: str, **overrides) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter, then back off on throttling.
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


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
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
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx provides for the account under test (not boto3's ambient
    chain): signing as the wrong principal makes the domain's account-scoped policy 403 the
    request.
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
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        # An HTTP status (above) is data the caller asserts on; a transport failure is not. The
        # endpoint here was published by the target itself, so failing to answer on it is the
        # target's failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has the
    access policy yet; signed requests can 403 for a while. Poll a cheap GET until it clears.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2)
    raise AssertionError(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]


# ===== end shared plumbing =====

# copied here so this file is self-contained =====


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Empty (including versions and delete markers) then delete; idempotent."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchBucket", "404"):
            raise


def _delete_role_quietly(iam, role_name: str) -> None:
    """Detach every inline policy, then delete the role; idempotent."""
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _snapshot_bucket_and_role(ctx, scenario: str) -> tuple:
    """A bucket plus an es.amazonaws.com-trusted role scoped to it. -> (bucket, role_arn)."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-behav-ossnap-")
    # Registered BEFORE the create, so a failure in between cannot leak the bucket.
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.create_bucket(Bucket=bucket,
                     CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]})

    role_name = ctx.unique_name("sim2real-behav-ossnap-")[:64]
    ctx.on_cleanup(lambda: _delete_role_quietly(iam, role_name))
    role = iam.create_role(
        RoleName=role_name,
        Description=f"sim2real {scenario} OpenSearch snapshot repository role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "es.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": scenario}])["Role"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListBucket"],
             "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow",
             "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                        "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
             "Resource": f"arn:aws:s3:::{bucket}/*"}]}))
    return bucket, role["Arn"]


def _register_repo(ctx, base: str, repo: str, bucket: str, role_arn: str, base_path: str) -> None:
    """Register an s3 snapshot repository, retrying only while IAM is still propagating.

    IAM exposes no condition that says "this role is now assumable by es.amazonaws.com", so the
    bounded retry on the engine's own refusal IS the wait -- there is nothing to poll. Anything other
    than that refusal is raised immediately rather than retried away.
    """
    deadline = time.monotonic() + 240.0
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _signed_request(ctx, "PUT", f"{base}/_snapshot/{repo}", body={
            "type": "s3",
            "settings": {"bucket": bucket, "region": ctx.region, "role_arn": role_arn,
                         "base_path": base_path}})
        if status == 200:
            return
        if status not in (500, 503):
            raise AssertionError(
                f"registering the s3 snapshot repository was refused with HTTP {status!r}, which is "
                f"not the IAM-propagation refusal this retry is for: {body!r}")
        time.sleep(2)
    raise AssertionError(
        f"snapshot repository {repo!r} could not be registered within 240s "
        f"(last HTTP {status!r}: {body!r})")


def _bulk_load(ctx, base: str, index: str, docs) -> None:
    lines = []
    for doc_id, source in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(source))
    status, body = _signed_request(ctx, "POST", f"{base}/_bulk?refresh=true",
                                   raw="\n".join(lines) + "\n",
                                   content_type="application/x-ndjson")
    assert status == 200, f"_bulk returned HTTP {status!r}, expected 200: {body!r}"
    assert body.get("errors") is False, (
        f"_bulk reported per-item errors loading {index!r}: "
        f"{[i for i in body.get('items', []) if 'error' in i.get('index', {})]!r}")


def _list_keys(s3, bucket: str, prefix: str) -> dict:
    """Every key under a prefix -> {key: size}. Paginated: no silent truncation at 1000."""
    keys = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            keys[obj["Key"]] = obj["Size"]
    return keys


# ===== end shared plumbing =====

_SCENARIO = "snapshot-bytes-land-in-s3"
_DOCS = [(f"snap-{i}", {"marker": f"snap-{i}", "n": i}) for i in range(5)]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A snapshot into an S3 repository writes every object under its declared `base_path`,
    verified through S3 itself; deleting the snapshot removes that data from S3, and reading the
    deleted snapshot fails 404 snapshot_missing_exception while restoring it fails 500 snapshot_restore_exception.

    Reference: https://docs.opensearch.org/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/
    """
    s3 = ctx.client("s3")
    bucket, role_arn = _snapshot_bucket_and_role(ctx, _SCENARIO)
    # A per-run prefix, so the containment assertion is about THIS repository's declared path.
    base_path = "sim2real/" + ctx.unique_name("snap-").replace("_", "-")

    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-snapbytes"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"marker": {"type": "keyword"}, "n": {"type": "integer"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))
    _bulk_load(ctx, base, index, _DOCS)

    # BASELINE at the consumer: the bucket is empty before the snapshot, so every object found later
    # was written by the snapshot and by nothing else.
    before = _list_keys(s3, bucket, "")
    assert before == {}, (
        f"the snapshot bucket already holds {sorted(before)!r} before any snapshot was taken; the "
        f"object-level assertions below need an empty baseline to attribute anything")

    repo = "sim2real-behav-snapbytes-repo"
    _register_repo(ctx, base, repo, bucket, role_arn, base_path)
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_snapshot/{repo}"))

    snap = "sim2real-behav-snap-1"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_snapshot/{repo}/{snap}"))
    status, taken = _signed_request(
        ctx, "PUT", f"{base}/_snapshot/{repo}/{snap}?wait_for_completion=true",
        body={"indices": index, "include_global_state": False})
    assert status == 200, f"taking snapshot {snap!r} returned HTTP {status!r}: {taken!r}"
    record = taken["snapshot"]
    assert record.get("state") == "SUCCESS", (
        f"snapshot {snap!r} reports state {record.get('state')!r}, expected 'SUCCESS': {record!r}")
    assert record["shards"]["failed"] == 0, (
        f"snapshot {snap!r} reports {record['shards']['failed']!r} failed shards, expected 0: "
        f"{record!r}")

    # TERMINAL READ AT THE CONSUMER: the objects, listed through the S3 API.
    after = _list_keys(s3, bucket, "")
    assert after, (
        f"snapshot {snap!r} reported SUCCESS and the bucket {bucket!r} is EMPTY -- a snapshot that "
        f"writes no bytes to the customer's bucket is not a snapshot")
    outside = sorted(k for k in after if not k.startswith(f"{base_path}/"))
    assert outside == [], (
        f"the snapshot wrote {outside!r} outside the declared base_path {base_path!r}; every object "
        f"must live under the prefix the repository was registered with")
    root_index_blobs = sorted(
        k for k in after
        if k.rsplit("/", 1)[-1].startswith("index") and k.count("/") == base_path.count("/") + 1)
    assert root_index_blobs, (
        f"no root-level index blob (index.latest / index-N) exists under {base_path!r}; the keys "
        f"present are {sorted(after)!r}")
    shard_data = sorted(k for k in after if k.startswith(f"{base_path}/indices/"))
    assert shard_data, (
        f"no objects exist under {base_path!r}/indices/, so the snapshot wrote metadata but no shard "
        f"data; the keys present are {sorted(after)!r}")
    assert sum(after[k] for k in shard_data) > 0, (
        f"the {len(shard_data)!r} objects under {base_path}/indices/ total zero bytes: "
        f"{ {k: after[k] for k in shard_data} !r}")

    # The snapshot is also listed by the OpenSearch API, so both sides agree it exists.
    status, listed = _signed_request(ctx, "GET", f"{base}/_snapshot/{repo}/{snap}")
    assert status == 200, f"GET snapshot {snap!r} returned HTTP {status!r}: {listed!r}"
    assert [s["snapshot"] for s in listed["snapshots"]] == [snap], (
        f"GET _snapshot/{repo}/{snap} lists {[s.get('snapshot') for s in listed['snapshots']]!r}, "
        f"expected exactly [{snap!r}]")

    # DELETE, then prove gone on BOTH sides.
    status, dropped = _signed_request(ctx, "DELETE", f"{base}/_snapshot/{repo}/{snap}")
    assert status == 200, f"DELETE snapshot {snap!r} returned HTTP {status!r}: {dropped!r}"
    assert dropped.get("acknowledged") is True, (
        f"DELETE snapshot {snap!r} reported acknowledged={dropped.get('acknowledged')!r}, expected "
        f"True: {dropped!r}")

    # The repository deletes blobs asynchronously, so this is a bounded poll with a stated reason that
    # RAISES -- not a sleep.
    deadline = time.monotonic() + 120.0
    remaining = shard_data
    while time.monotonic() < deadline:
        remaining = sorted(_list_keys(s3, bucket, f"{base_path}/indices/"))
        if not remaining:
            break
        time.sleep(5.0)
    assert remaining == [], (
        f"120s after deleting snapshot {snap!r}, S3 still holds {remaining!r} under "
        f"{base_path}/indices/ -- deleting a snapshot must release the customer's storage")

    status, gone = _signed_request(ctx, "GET", f"{base}/_snapshot/{repo}/{snap}")
    assert status == 404, (
        f"GET of the deleted snapshot {snap!r} returned HTTP {status!r}, expected 404: {gone!r}")
    assert _error_type(gone) == "snapshot_missing_exception", (
        f"GET of the deleted snapshot reports error type {_error_type(gone)!r}, expected "
        f"'snapshot_missing_exception': {gone!r}")
    gone_reason = (gone.get("error", {}) or {}).get("reason")
    expected_gone_reason = f"[{repo}:{snap}] is missing"
    assert gone_reason == expected_gone_reason, (
        f"GET of the deleted snapshot reports reason {gone_reason!r}, expected "
        f"{expected_gone_reason!r}: {gone!r}")
    # A MUTATION on the dead id must fail too, not merely a read -- but restore's failure is reported
    # through a DIFFERENT exception than the plain GET above: real AWS wraps the missing-snapshot
    # lookup in `snapshot_restore_exception` and answers HTTP 500, not GET's HTTP 404
    # `snapshot_missing_exception`.
    status, restore_dead = _signed_request(
        ctx, "POST", f"{base}/_snapshot/{repo}/{snap}/_restore?wait_for_completion=true",
        body={"indices": index, "rename_pattern": index, "rename_replacement": f"{index}-restored"})
    assert status == 500, (
        f"restoring the deleted snapshot {snap!r} returned HTTP {status!r}, expected 500: "
        f"{restore_dead!r}")
    assert _error_type(restore_dead) == "snapshot_restore_exception", (
        f"restoring the deleted snapshot reports error type {_error_type(restore_dead)!r}, expected "
        f"'snapshot_restore_exception': {restore_dead!r}")
    restore_reason = (restore_dead.get("error", {}) or {}).get("reason")
    expected_restore_reason = f"[{repo}:{snap}] snapshot does not exist"
    assert restore_reason == expected_restore_reason, (
        f"restoring the deleted snapshot {snap!r} reports reason {restore_reason!r}, expected "
        f"{expected_restore_reason!r}: {restore_dead!r}")
    status, not_restored = _signed_request(ctx, "GET", f"{base}/{index}-restored/_count")
    assert status == 404, (
        f"the restore of a deleted snapshot created {index}-restored anyway (HTTP {status!r}): "
        f"{not_restored!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
