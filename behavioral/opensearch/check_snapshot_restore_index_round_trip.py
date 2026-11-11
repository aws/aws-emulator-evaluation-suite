"""snapshot-restore-index-round-trip."""
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

CHECK = "snapshot-restore-index-round-trip"
GROUP = 'data-plane'
SERVICES = ['opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology: domains bill per node-hour.
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
# Control-plane counterpart, for a domain that was accepted and never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """Failure for a resource that never reached its ready state.

    Returned rather than raised, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created or is already deleted.

    Any other delete failure is raised so a leaked cluster is visible in the run log.
    """
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
    # Registered BEFORE the create so a failure between create and registration can never leak a
    # 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        # Tagged at creation so tag-based cleanup can find it.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: back off on throttling.
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
    """Poll to Processing=False AND a published Endpoint; never a bare sleep.

    Provisioning this topology takes ~680-850 s; the budget keeps the whole check under 30 minutes.
    """
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials, not boto3's ambient chain: the wrong principal gets a 403
    from the domain's account-scoped policy.
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
        # The endpoint was published by the service itself, so not answering on it is a failure
        # of the service, not of the caller's environment.
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
        time.sleep(2.0)
    raise _never_ready(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _error_type(payload) -> str:
    """The ``error.type`` of an OpenSearch engine error body (the wrapper, not the root cause)."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _root_cause_type(payload) -> str:
    """The FIRST root-cause type, for the exceptions the engine wraps one level deep."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        causes = error.get("root_cause") or []
        if causes and isinstance(causes[0], dict):
            return str(causes[0].get("type") or "")
    return ""


def _bulk_load(ctx, base: str, index: str, docs) -> None:
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


def _wait_index_status(ctx, base: str, index: str, want: str, timeout_s: float = 180.0) -> dict:
    """Poll _cluster/health for one index until it reaches a status; never a bare sleep.

    Bounded by the engine's own ``wait_for_status`` timeout inside a bounded outer loop, so a
    target that answers but never allocates fails rather than hangs.
    """
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        status, last = _signed_request(
            ctx, "GET", f"{base}/_cluster/health/{index}?wait_for_status={want}&timeout=30s")
        if status == 200 and last.get("timed_out") is False:
            return last
        time.sleep(2.0)
    raise _never_ready(
        f"index {index!r} did not reach status {want!r} within {timeout_s}s (last health {last!r})",
    )


def _hit_ids(result) -> list:
    return [h["_id"] for h in result.get("hits", {}).get("hits", [])]


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Empty (including versions and delete markers) then delete; idempotent."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
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


def _register_repo(ctx, base: str, repo: str, bucket: str, role_arn: str) -> None:
    """Register an s3 snapshot repository, retrying only while IAM is still propagating.

    IAM exposes no condition that says "this role is now assumable by es.amazonaws.com", so the
    bounded retry on the engine's own refusal IS the wait -- there is nothing to poll. Anything
    other than that refusal is raised immediately rather than retried away.
    """
    deadline = time.monotonic() + 240.0
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _signed_request(ctx, "PUT", f"{base}/_snapshot/{repo}", body={
            "type": "s3",
            "settings": {"bucket": bucket, "region": ctx.region, "role_arn": role_arn}})
        if status == 200:
            return
        if status not in (500, 503):
            raise AssertionError(
                f"registering the s3 snapshot repository was refused with HTTP {status!r}, which "
                f"is not the IAM-propagation refusal this retry is for: {body!r}")
        time.sleep(2.0)
    raise _never_ready(
        f"snapshot repository {repo!r} could not be registered within 240s "
        f"(last HTTP {status!r}: {body!r})")


def _take_snapshot(ctx, base: str, repo: str, snap: str, index: str) -> dict:
    """Snapshot one index synchronously and return the snapshot record."""
    status, body = _signed_request(
        ctx, "PUT", f"{base}/_snapshot/{repo}/{snap}?wait_for_completion=true",
        body={"indices": index, "include_global_state": False})
    assert status == 200, f"taking snapshot {snap!r} returned HTTP {status!r}: {body!r}"
    return body.get("snapshot", {})


def _restore(ctx, base: str, repo: str, snap: str, index: str, **extra) -> tuple:
    body = {"indices": index}
    body.update(extra)
    return _signed_request(
        ctx, "POST", f"{base}/_snapshot/{repo}/{snap}/_restore?wait_for_completion=true",
        body=body)


_SCENARIO = "snapshot-restore-round-trip"


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An index snapshotted to an S3 repository, deleted, then restored holds exactly its five
    documents with identical _source values, proving the data survived the delete.
    """
    s3_bucket, role_arn = _snapshot_bucket_and_role(ctx, _SCENARIO)
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-snap"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"n": {"type": "integer"}, "tag": {"type": "keyword"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"

    expected_sources = {f"snap-{i}": {"n": i, "tag": f"v{i}"} for i in range(5)}
    _bulk_load(ctx, base, index, sorted(expected_sources.items()))
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh before the snapshot returned HTTP {status!r}"

    repo, snap = "sim2real-behav-repo", "sim2real-behav-snap-1"
    _register_repo(ctx, base, repo, s3_bucket, role_arn)
    # Deleted before the bucket (LIFO cleanup runs these first) so the bucket empties cleanly.
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_snapshot/{repo}"))
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_snapshot/{repo}/{snap}"))

    record = _take_snapshot(ctx, base, repo, snap, index)
    assert record.get("state") == "SUCCESS", (
        f"the snapshot finished in state {record.get('state')!r}, expected SUCCESS: {record!r}"
    )
    assert record.get("indices") == [index], (
        f"the snapshot records indices {record.get('indices')!r}, expected exactly [{index!r}]"
    )
    assert record.get("failures") == [], (
        f"the snapshot reported shard failures: {record.get('failures')!r}"
    )
    shards = record.get("shards", {})
    assert (shards.get("successful"), shards.get("failed")) == (1, 0), (
        f"the snapshot reports shards {shards!r}, expected one successful and none failed"
    )

    # Destroy the source; the 404 proves a no-op restore over a still-present index cannot pass.
    status, deleted = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"deleting the index returned HTTP {status!r}: {deleted!r}"
    status, gone = _signed_request(ctx, "GET", f"{base}/{index}/_doc/snap-0")
    assert status == 404, (
        f"a known document was still readable after the index DELETE (HTTP {status!r}), so the "
        f"restore below would prove nothing: {gone!r}"
    )

    status, restored = _restore(ctx, base, repo, snap, index)
    assert status == 200, f"the restore returned HTTP {status!r}: {restored!r}"
    restore_record = restored.get("snapshot", {})
    assert restore_record.get("shards", {}).get("successful") == 1, (
        f"the restore reports shards {restore_record.get('shards')!r}, expected one successful"
    )
    _wait_index_status(ctx, base, index, "yellow")
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh after the restore returned HTTP {status!r}"

    status, search = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                     body={"size": 20, "query": {"match_all": {}}})
    assert status == 200, f"searching the restored index returned HTTP {status!r}: {search!r}"
    assert sorted(_hit_ids(search)) == sorted(expected_sources), (
        f"the restored index holds {sorted(_hit_ids(search))!r}, expected exactly the five "
        f"snapshotted ids {sorted(expected_sources)!r}"
    )
    restored_sources = {h["_id"]: h["_source"] for h in search["hits"]["hits"]}
    assert restored_sources == expected_sources, (
        f"the restored _source values differ from what was snapshotted: {restored_sources!r} != "
        f"{expected_sources!r} -- a durable snapshot returns the documents, not just their ids"
    )
    status, count = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"_count on the restored index returned HTTP {status!r}: {count!r}"
    assert count.get("count") == 5, (
        f"_count after the restore is {count.get('count')!r}, expected 5"
    )

    status, listed = _signed_request(ctx, "GET", f"{base}/_snapshot/{repo}/{snap}")
    assert status == 200, f"reading the snapshot back returned HTTP {status!r}: {listed!r}"
    listed_names = [s.get("snapshot") for s in listed.get("snapshots", [])]
    assert listed_names == [snap], (
        f"the repository lists {listed_names!r}, expected exactly [{snap!r}]"
    )

    _signed_request(ctx, "DELETE", f"{base}/{index}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
