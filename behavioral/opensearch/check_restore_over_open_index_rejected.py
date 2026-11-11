"""restore-over-open-index-rejected."""
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

CHECK = "restore-over-open-index-rejected"
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

# Marks a published domain endpoint that failed to answer as a failure of the target.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
# Marks a domain that was accepted but never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The failure for a resource that never reached its ready state, returned for ``raise``."""
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate only a domain that was never created or is already deleted."""
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
    # Registered before the create so a failure in between cannot leak a running cluster.
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


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False and a published Endpoint.

    Provisioning this topology takes roughly 680-850 s, hence the budget.
    """
    osc = ctx.client("opensearch")
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            # fixed-wait: DescribeDomain throttles under the suite's concurrent polls; back off, then poll
            time.sleep(15.0)
            continue
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        # fixed-wait: DescribeDomain is rate-limited and provisioning takes minutes, so read every 15 s
        time.sleep(15.0)
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials: the wrong principal is 403'd by the account-scoped policy.
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
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
        # The endpoint did not answer at all. The target published it, so that is the target's failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Poll a cheap GET until it stops 403ing: the access policy reaches the data plane late."""
    timeout_s = _budget_s(ctx, timeout_s)
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
    """The ``error.type`` of an OpenSearch engine error body, or ''."""
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
    """Poll _cluster/health for one index until it reaches a status, within a bounded loop."""
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

    IAM exposes no readiness signal for the role, so the bounded retry on a 500/503 is the wait.
    """
    deadline = time.monotonic() + _budget_s(ctx, 240.0)
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


_SCENARIO = "restore-over-open-index-rejected"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Restoring a snapshot over an open index of the same name is refused (500
    snapshot_restore_exception) leaving the live index untouched, while the same snapshot restores
    under a new name with its original documents.

    Reference: https://docs.opensearch.org/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/
    """
    s3_bucket, role_arn = _snapshot_bucket_and_role(ctx, _SCENARIO)
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-restover"
    copy = f"{index}-copy"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"n": {"type": "integer"}, "tag": {"type": "keyword"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"

    snapshotted = {f"ro-{i}": {"n": i, "tag": "original"} for i in range(3)}
    _bulk_load(ctx, base, index, sorted(snapshotted.items()))
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh before the snapshot returned HTTP {status!r}"

    repo, snap = "sim2real-behav-repo", "sim2real-behav-snap-1"
    _register_repo(ctx, base, repo, s3_bucket, role_arn)
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_snapshot/{repo}"))
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_snapshot/{repo}/{snap}"))
    record = _take_snapshot(ctx, base, repo, snap, index)
    assert record.get("state") == "SUCCESS", (
        f"the snapshot finished in state {record.get('state')!r}, expected SUCCESS: {record!r}"
    )

    # Make the LIVE index differ from the snapshot, so a rollback would be observable.
    mutated_source = {"n": 0, "tag": "mutated-after-snapshot"}
    status, overwritten = _signed_request(ctx, "PUT", f"{base}/{index}/_doc/ro-0",
                                          body=mutated_source)
    assert status == 200, f"overwriting the live document returned HTTP {status!r}: {overwritten!r}"
    assert overwritten.get("_version") == 2, (
        f"the overwrite reported _version {overwritten.get('_version')!r}, expected 2"
    )
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh after the overwrite returned HTTP {status!r}"

    # Real AWS answers 500 snapshot_restore_exception here, not 400 resource_already_exists.
    status, refused = _restore(ctx, base, repo, snap, index)
    assert status == 500, (
        f"restoring over an open index returned HTTP {status!r}, expected "
        f"500: {refused!r}"
    )
    assert _error_type(refused) == "snapshot_restore_exception", (
        f"expected snapshot_restore_exception, got {_error_type(refused)!r}: {refused!r}"
    )

    # Effect absent: the refused restore did not touch the live index.
    status, live = _signed_request(ctx, "GET", f"{base}/{index}/_doc/ro-0")
    assert status == 200, f"the live document is unreadable after the refusal ({status!r}): {live!r}"
    assert live.get("_source") == mutated_source, (
        f"the live index was modified by a REFUSED restore: {live.get('_source')!r} != "
        f"{mutated_source!r}"
    )
    assert live.get("_version") == 2, (
        f"the live document is at _version {live.get('_version')!r}, expected 2 -- a refused "
        f"restore must not reset it"
    )
    status, count = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"_count on the live index returned HTTP {status!r}: {count!r}"
    assert count.get("count") == 3, (
        f"the live index holds {count.get('count')!r} documents after the refusal, expected 3"
    )

    # Positive control: the SAME snapshot restores fine under a different name, so the refusal is
    # attributable to the collision alone.
    status, renamed = _restore(ctx, base, repo, snap, index,
                               rename_pattern=index, rename_replacement=copy)
    assert status == 200, (
        f"the positive-control renamed restore returned HTTP {status!r}, so the refusal above "
        f"cannot be attributed to the name collision: {renamed!r}"
    )
    _wait_index_status(ctx, base, copy, "yellow")
    status, _ = _signed_request(ctx, "POST", f"{base}/{copy}/_refresh")
    assert status == 200, f"_refresh of the restored copy returned HTTP {status!r}"
    status, search = _signed_request(ctx, "POST", f"{base}/{copy}/_search",
                                     body={"size": 20, "query": {"match_all": {}}})
    assert status == 200, f"searching the restored copy returned HTTP {status!r}: {search!r}"
    assert sorted(_hit_ids(search)) == sorted(snapshotted), (
        f"the positive-control restore returned {sorted(_hit_ids(search))!r}, expected "
        f"{sorted(snapshotted)!r} -- the snapshot itself is restorable"
    )
    copy_sources = {h["_id"]: h["_source"] for h in search["hits"]["hits"]}
    assert copy_sources == snapshotted, (
        f"the restored copy holds {copy_sources!r}, expected the pre-mutation snapshot content "
        f"{snapshotted!r} -- the snapshot must carry the values as of when it was taken"
    )

    for name in (copy, index):
        _signed_request(ctx, "DELETE", f"{base}/{name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
