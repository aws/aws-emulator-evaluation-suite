"""s3c-batch-generated-manifest-filter-limits-job-to-matching-objects."""
from __future__ import annotations

import csv
import gzip
import io
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3c-batch-generated-manifest-filter-limits-job-to-matching-objects"
GROUP = "state-machine"
SERVICES = ["s3control"]

#: A generated-manifest job enumerates the source bucket during Preparing before any task runs.
_JOB_TERMINAL_TIMEOUT_S = 600
_MANIFEST_TIMEOUT_S = 300
_ROLE_ASSUME_RETRY_TIMEOUT_S = 240

_MANIFEST_PREFIX = "genmanifest"
_REPORT_PREFIX = "reports"
_MATCHED_PREFIX = "inc/"
_MATCHED_KEYS = ["inc/first.txt", "inc/second.txt"]
_UNMATCHED_KEYS = ["skip/third.txt", "skip/fourth.txt"]
_JOB_TAG = {"Key": "sim2real-generated", "Value": "matched"}


@tags(
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:happy-path",
)
def run(ctx) -> None:
    """A generated-manifest job tags only objects matching its KeyNameConstraint, leaves the rest
    untagged, and writes a manifest object naming exactly the matched keys."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    src = ctx.unique_name("sim2real-behav-bgmsrc-")
    aux = ctx.unique_name("sim2real-behav-bgmaux-")
    role = ctx.unique_name("sim2real-behav-bgmrole-")

    _create_bucket(ctx, s3, src)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src))
    # The generated manifest and the completion report go to a SEPARATE bucket, so the source
    # bucket holds only the four objects under test and the enumeration cannot see its own output.
    _create_bucket(ctx, s3, aux)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, aux))

    for key in _MATCHED_KEYS + _UNMATCHED_KEYS:
        s3.put_object(Bucket=src, Key=key, Body=f"body of {key}\n".encode())
    for key in _MATCHED_KEYS + _UNMATCHED_KEYS:
        existing = s3.get_object_tagging(Bucket=src, Key=key)["TagSet"]
        assert existing == [], f"{key!r} already carried tags {existing!r} before the job ran"

    role_arn = _batch_role(ctx, iam, role, [src, aux])

    job_id = _create_job_surviving_role_propagation(
        ctx,
        s3c,
        account,
        dict(
            AccountId=account,
            ConfirmationRequired=False,
            Operation={"S3PutObjectTagging": {"TagSet": [_JOB_TAG]}},
            Report={
                "Bucket": f"arn:aws:s3:::{aux}",
                "Format": "Report_CSV_20180820",
                "Enabled": True,
                "Prefix": _REPORT_PREFIX,
                "ReportScope": "AllTasks",
            },
            ManifestGenerator={
                "S3JobManifestGenerator": {
                    "ExpectedBucketOwner": account,
                    "SourceBucket": f"arn:aws:s3:::{src}",
                    "ManifestOutputLocation": {
                        "ExpectedManifestBucketOwner": account,
                        "Bucket": f"arn:aws:s3:::{aux}",
                        "ManifestPrefix": _MANIFEST_PREFIX,
                        "ManifestFormat": "S3InventoryReport_CSV_20211130",
                    },
                    "Filter": {"KeyNameConstraint": {"MatchAnyPrefix": [_MATCHED_PREFIX]}},
                    "EnableManifestOutput": True,
                }
            },
            Priority=10,
            RoleArn=role_arn,
            Description="sim2real-behav generated manifest job",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
    )
    job = _poll_terminal(s3c, account, job_id)

    assert job["Status"] == "Complete", (
        f"the job settled into {job['Status']!r} (reasons {job.get('FailureReasons')!r}), "
        "expected Complete"
    )
    summary = job.get("ProgressSummary", {})
    assert summary.get("TotalNumberOfTasks") == len(_MATCHED_KEYS), (
        f"ProgressSummary reported {summary!r}, expected {len(_MATCHED_KEYS)} tasks — the filter "
        f"matches only {_MATCHED_PREFIX!r}, and the bucket holds "
        f"{len(_MATCHED_KEYS) + len(_UNMATCHED_KEYS)} objects"
    )
    assert summary.get("NumberOfTasksSucceeded") == len(_MATCHED_KEYS), (
        f"ProgressSummary reported {summary!r}, expected every generated task to succeed"
    )
    assert summary.get("NumberOfTasksFailed") == 0, (
        f"ProgressSummary reported {summary!r}, expected zero failed tasks"
    )

    # The operation actually ran over the matched objects...
    for key in _MATCHED_KEYS:
        got = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=src, Key=key)["TagSet"]}
        assert got == {_JOB_TAG["Key"]: _JOB_TAG["Value"]}, (
            f"{key!r} carries tags {got!r} after the job, expected the job's single tag"
        )

    # ...and the ABSENCE is the point: an object the filter excluded was never touched.
    for key in _UNMATCHED_KEYS:
        got = s3.get_object_tagging(Bucket=src, Key=key)["TagSet"]
        assert got == [], (
            f"{key!r} carries tags {got!r}, but it is outside {_MATCHED_PREFIX!r} and must never "
            "have entered the generated manifest"
        )

    # The generated manifest is an OBJECT, and it names exactly the matched keys.
    generated = _read_generated_manifest(s3, aux, _MANIFEST_PREFIX, job_id)
    assert sorted(generated["keys"]) == sorted(_MATCHED_KEYS), (
        f"the generated manifest lists {sorted(generated['keys'])!r}, expected exactly "
        f"{sorted(_MATCHED_KEYS)!r}"
    )
    assert generated["buckets"] == {src}, (
        f"the generated manifest names buckets {generated['buckets']!r}, expected only {src!r}"
    )
    # AWS asymmetry, worth pinning because nothing in the model implies it: the descriptor
    # reports its SOURCE bucket as a bare name and its DESTINATION bucket as an ARN, even though
    # both were supplied to CreateJob as ARNs.
    assert generated["source_bucket"] == src, (
        f"the generated manifest's own manifest.json reports sourceBucket "
        f"{generated['source_bucket']!r}, expected the bare bucket name {src!r}"
    )
    assert generated["destination_bucket"] == f"arn:aws:s3:::{aux}", (
        f"the generated manifest's own manifest.json reports destinationBucket "
        f"{generated['destination_bucket']!r}, expected the ARN 'arn:aws:s3:::{aux}'"
    )


# ===== helpers =====

def _poll_terminal(s3c, account: str, job_id: str, timeout_s: float = _JOB_TERMINAL_TIMEOUT_S):
    deadline = time.monotonic() + timeout_s
    job = None
    while time.monotonic() < deadline:
        job = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]
        if job["Status"] in ("Complete", "Failed", "Cancelled"):
            return job
        time.sleep(4)
    raise AssertionError(
        f"job {job_id} did not reach a terminal state within {timeout_s}s; last observed status "
        f"{(job or {}).get('Status')!r}"
    )


def _create_job_surviving_role_propagation(
    ctx, s3c, account: str, params: dict, timeout_s: float = _ROLE_ASSUME_RETRY_TIMEOUT_S
) -> str:
    """CreateJob, retried while the freshly created batch role propagates.

    IAM propagation exposes no condition to poll. CreateJob validates the role synchronously and
    raises BadRequestException until it is usable; separately, a job can be accepted and then fail
    terminally because the batch operations service could not assume the role yet. Both arms are
    bounded here, over the job's own observable outcome rather than a fixed sleep.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            job_id = s3c.create_job(**params)["JobId"]
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            if last != "BadRequestException":
                raise
            time.sleep(5)
            continue
        ctx.on_cleanup(lambda jid=job_id: _cancel_job(s3c, account, jid))
        job = _poll_terminal(s3c, account, job_id)
        if not _role_not_yet_assumable(job):
            return job_id
        last = "AccessDenied (could not assume the IAM role)"
        time.sleep(2)
    raise AssertionError(
        f"CreateJob never produced a job that could assume its role within {timeout_s}s; last "
        f"observed {last!r}"
    )


def _role_not_yet_assumable(job: dict) -> bool:
    return job["Status"] == "Failed" and any(
        r.get("FailureCode") == "AccessDenied"
        and (
            # the operation stage and the generated-manifest stage word the propagation failure differently
            "assume the IAM role" in r.get("FailureReason", "")
            or "Failed to assume role." in r.get("FailureReason", "")
        )
        for r in job.get("FailureReasons") or []
    )


def _cancel_job(s3c, account: str, job_id: str) -> None:
    try:
        status = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]["Status"]
        if status in ("New", "Preparing", "Suspended", "Ready", "Active", "Paused"):
            s3c.update_job_status(
                AccountId=account,
                JobId=job_id,
                RequestedJobStatus="Cancelled",
                StatusUpdateReason="sim2real behav teardown",
            )
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "InvalidRequest" and err.get("Message") == "Job not found":
            return
        # A job that turned terminal between the read and the cancel needs nothing more.
        if err["Code"] != "InvalidRequest" or s3c.describe_job(AccountId=account, JobId=job_id)[
            "Job"
        ]["Status"] not in ("Complete", "Completing", "Failed", "Failing", "Cancelled", "Cancelling"):
            raise


def _read_generated_manifest(
    s3, bucket: str, prefix: str, job_id: str, timeout_s: float = _MANIFEST_TIMEOUT_S
) -> dict:
    """The keys the service wrote into the generated manifest, read through its own manifest.json.

    The generated manifest is an S3-Inventory-shaped bundle: a manifest.json naming a schema and
    the data files, plus one or more CSV parts that may be gzipped. Both the file list and the
    column names are taken from manifest.json rather than assumed, and the parse is asserted.
    """
    # The bundle's own layout under ManifestPrefix is the service's to choose, so it is DISCOVERED
    # by listing rather than assumed — and the discovered key must name this job, which is itself
    # an assertion that the manifest belongs to the job just run.
    deadline = time.monotonic() + timeout_s
    manifest_key = None
    seen: list[str] = []
    while time.monotonic() < deadline:
        seen = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
            seen += [o["Key"] for o in page.get("Contents", [])]
        candidates = [k for k in seen if k.endswith("manifest.json")]
        if candidates:
            assert len(candidates) == 1, (
                f"expected one generated manifest.json under {prefix!r}, found {candidates!r}"
            )
            manifest_key = candidates[0]
            break
        time.sleep(5)
    assert manifest_key, (
        f"no generated manifest.json appeared under {prefix!r} within {timeout_s}s; the prefix "
        f"held {sorted(seen)!r}"
    )
    assert job_id in manifest_key, (
        f"the generated manifest landed at {manifest_key!r}, which does not name job {job_id!r}"
    )
    doc = json.loads(s3.get_object(Bucket=bucket, Key=manifest_key)["Body"].read())

    # AWS field naming, asserted rather than tolerated: the generated manifest's own
    # descriptor is camelCase (`fileSchema`, `files`, `sourceBucket`) — unlike the job COMPLETION
    # report's manifest.json, which is PascalCase. An emulator that emits one casing for both is
    # diverging, so accepting either here would hide it.
    assert doc.get("fileFormat") == "CSV", (
        f"the generated manifest declares fileFormat {doc.get('fileFormat')!r}, expected 'CSV'"
    )
    schema_raw = doc.get("fileSchema")
    assert schema_raw, f"the generated manifest carries no 'fileSchema': {doc!r}"
    schema = [c.strip() for c in schema_raw.split(",")]
    for column in ("Bucket", "Key"):
        assert column in schema, (
            f"the generated manifest's fileSchema {schema!r} has no {column!r} column"
        )

    files = doc.get("files")
    assert files, f"the generated manifest lists no 'files': {doc!r}"

    keys: list[str] = []
    buckets: set[str] = set()
    for entry in files:
        entry_key = entry.get("key")
        assert entry_key, f"a generated manifest file entry names no 'key': {entry!r}"
        raw = s3.get_object(Bucket=bucket, Key=entry_key)["Body"].read()
        # The data parts are gzipped; decompress on the magic bytes and assert the parse below
        # rather than trusting the extension.
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        for row in csv.reader(io.StringIO(raw.decode())):
            if not row:
                continue
            assert len(row) == len(schema), (
                f"generated manifest row {row!r} has {len(row)} columns, but the schema declares "
                f"{len(schema)}: {schema!r}"
            )
            by_name = dict(zip(schema, row))
            buckets.add(by_name["Bucket"])
            keys.append(by_name["Key"])
    assert keys, f"the generated manifest's data files under {manifest_key!r} held no rows"
    return {
        "keys": keys,
        "buckets": buckets,
        "source_bucket": doc.get("sourceBucket"),
        "destination_bucket": doc.get("destinationBucket"),
    }


def _batch_role(ctx, iam, role: str, buckets: list[str]) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "batchoperations.s3.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(trust))["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    resources = [f"arn:aws:s3:::{b}" for b in buckets] + [f"arn:aws:s3:::{b}/*" for b in buckets]
    iam.put_role_policy(
        RoleName=role,
        PolicyName="batch",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:GetObjectVersion",
                            "s3:GetObjectTagging",
                            "s3:PutObject",
                            "s3:PutObjectTagging",
                            # A generated manifest carries a VersionId column, so the tasks are
                            # version-qualified even on an unversioned bucket and the version-
                            # scoped tagging permissions are the ones actually evaluated.
                            "s3:PutObjectVersionTagging",
                            "s3:GetObjectVersionTagging",
                            "s3:GetBucketLocation",
                            "s3:ListBucket",
                            "s3:ListBucketVersions",
                            "s3:GetBucketVersioning",
                            # AWS behaviour NOT in the model: a generated manifest
                            # fails during Preparing with FailureCode AccessDenied and
                            # "s3:PutInventoryConfiguration required for the role" unless the job
                            # role also carries that bucket-level permission on the source.
                            "s3:PutInventoryConfiguration",
                        ],
                        "Resource": resources,
                    }
                ],
            }
        ),
    )
    # IAM propagation exposes no condition to poll; _create_job_surviving_role_propagation is the
    # bounded wait for it.
    return role_arn


def _delete_role(iam, role: str) -> None:
    try:
        for name in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role, PolicyName=name)
        iam.delete_role(RoleName=role)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
