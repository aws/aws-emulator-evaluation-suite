"""s3c-batch-copy-job-copies-manifest-objects-and-leaves-the-rest."""
from __future__ import annotations

import csv
import io
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3c-batch-copy-job-copies-manifest-objects-and-leaves-the-rest"
GROUP = "state-machine"
SERVICES = ["s3control"]

#: A Batch Operations job walks New -> Preparing -> Active -> Complete on the service's own
#: clock, and the completion report lands after that.
_JOB_TERMINAL_TIMEOUT_S = 600
_REPORT_TIMEOUT_S = 300
_ROLE_ASSUME_RETRY_TIMEOUT_S = 240

_TARGET_PREFIX = "copied"
_REPORT_PREFIX = "reports"
#: Bodies differ in length as well as content, so a copy that swapped two keys cannot pass.
_PAYLOADS = {
    "src/one.txt": b"one\n",
    "src/two.txt": b"two-two-two\n",
    "src/three.txt": b"three-three-three-three\n",
}
#: The two rows actually submitted in the manifest. "src/three.txt" is deliberately omitted.
_MANIFEST_KEYS = ["src/one.txt", "src/two.txt"]
_OMITTED_KEY = "src/three.txt"


@tags("cap:c3", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """A Batch copy job writes byte-identical, ETag-matching copies of only the manifest's objects
    under TargetKeyPrefix, leaves sources intact, and reports exactly the submitted rows."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    src = ctx.unique_name("sim2real-behav-bcpsrc-")
    dst = ctx.unique_name("sim2real-behav-bcpdst-")
    role = ctx.unique_name("sim2real-behav-bcprole-")

    _create_bucket(ctx, s3, src)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src))
    _create_bucket(ctx, s3, dst)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, dst))

    source_etags = {}
    for key, body in _PAYLOADS.items():
        source_etags[key] = s3.put_object(Bucket=src, Key=key, Body=body)["ETag"].strip('"')

    # The destination must start empty for the "nothing else was written" assertions to mean
    # anything, and it is a bucket this check just created, so emptiness is a property of the
    # query rather than of the account.
    pre = _list_keys(s3, dst)
    assert pre == [], f"the destination bucket this check created already held {pre!r}"

    manifest_body = "".join(f"{src},{k}\n" for k in _MANIFEST_KEYS).encode()
    manifest_etag = s3.put_object(
        Bucket=src, Key="manifest.csv", Body=manifest_body
    )["ETag"].strip('"')

    role_arn = _batch_role(ctx, iam, role, [src, dst])

    job_id = _create_job_surviving_role_propagation(
        ctx,
        s3c,
        account,
        dict(
            AccountId=account,
            ConfirmationRequired=False,
            Operation={
                "S3PutObjectCopy": {
                    "TargetResource": f"arn:aws:s3:::{dst}",
                    "TargetKeyPrefix": _TARGET_PREFIX,
                }
            },
            Report={
                "Bucket": f"arn:aws:s3:::{dst}",
                "Format": "Report_CSV_20180820",
                "Enabled": True,
                "Prefix": _REPORT_PREFIX,
                "ReportScope": "AllTasks",
            },
            Manifest={
                "Spec": {
                    "Format": "S3BatchOperations_CSV_20180820",
                    "Fields": ["Bucket", "Key"],
                },
                "Location": {
                    "ObjectArn": f"arn:aws:s3:::{src}/manifest.csv",
                    "ETag": manifest_etag,
                },
            },
            Priority=10,
            RoleArn=role_arn,
            Description="sim2real-behav batch copy execution",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
    )
    job = _poll_terminal(s3c, account, job_id)

    assert job["Status"] == "Complete", (
        f"the copy job settled into {job['Status']!r} (reasons {job.get('FailureReasons')!r}), "
        "expected Complete"
    )
    summary = job.get("ProgressSummary", {})
    assert summary.get("TotalNumberOfTasks") == len(_MANIFEST_KEYS), (
        f"ProgressSummary reported {summary!r}, expected {len(_MANIFEST_KEYS)} tasks — one per "
        "manifest row"
    )
    assert summary.get("NumberOfTasksSucceeded") == len(_MANIFEST_KEYS), (
        f"ProgressSummary reported {summary!r}, expected every task to succeed"
    )
    assert summary.get("NumberOfTasksFailed") == 0, (
        f"ProgressSummary reported {summary!r}, expected zero failed tasks"
    )

    # The point of the check: the job actually moved BYTES. Read each copy back and compare to the
    # source payload, and compare ETags so a truncated or re-encoded copy cannot pass.
    for key in _MANIFEST_KEYS:
        copied = f"{_TARGET_PREFIX}/{key}"
        got = s3.get_object(Bucket=dst, Key=copied)
        body = got["Body"].read()
        assert body == _PAYLOADS[key], (
            f"the copy at {copied!r} holds {body!r}, expected the source bytes {_PAYLOADS[key]!r}"
        )
        assert got["ETag"].strip('"') == source_etags[key], (
            f"the copy at {copied!r} has ETag {got['ETag']!r}, expected the source's "
            f"{source_etags[key]!r}"
        )

    # Effect ABSENT for the row that was never submitted: no counterpart under the target prefix.
    missing = _error_code(
        lambda: s3.head_object(Bucket=dst, Key=f"{_TARGET_PREFIX}/{_OMITTED_KEY}")
    )
    assert missing == "404", (
        f"heading the unsubmitted key's destination returned {missing!r}, expected '404' — the "
        "job must copy only the manifest's rows"
    )

    # Every source object is still exactly as it was: a copy job is not a move.
    for key, body in _PAYLOADS.items():
        still = s3.get_object(Bucket=src, Key=key)["Body"].read()
        assert still == body, (
            f"source object {key!r} now holds {still!r}, expected {body!r} — a copy job must not "
            "mutate the source"
        )

    # The completion report's per-object rows are exactly the rows submitted.
    report = _read_completion_report(s3, dst, _REPORT_PREFIX, job_id)
    reported = sorted((r["bucket"], r["key"]) for r in report)
    assert reported == sorted((src, k) for k in _MANIFEST_KEYS), (
        f"the completion report accounts for {reported!r}, expected exactly the submitted rows "
        f"{sorted((src, k) for k in _MANIFEST_KEYS)!r}"
    )
    statuses = {r["status"] for r in report}
    assert statuses == {"200"}, (
        f"the completion report's HTTP status column held {statuses!r}, expected every row to be "
        "'200'"
    )


# ===== helpers =====

def _error_code(fn) -> str:
    """The AWS error code a call raises. Raises when the call SUCCEEDS, because a falsy sentinel
    would turn "the target accepted input real AWS rejects" into a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS refuses it")


def _list_keys(s3, bucket: str) -> list[str]:
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return sorted(keys)


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


# A not-yet-propagated role fails the job with either wording.
_UNASSUMABLE_REASONS = (
    "assume the IAM role",
    "allows batchoperations.s3.amazonaws.com to assume the role",
)


def _role_not_yet_assumable(job: dict) -> bool:
    return job["Status"] == "Failed" and any(
        r.get("FailureCode") == "AccessDenied"
        and any(reason in r.get("FailureReason", "") for reason in _UNASSUMABLE_REASONS)
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


def _read_completion_report(
    s3, bucket: str, prefix: str, job_id: str, timeout_s: float = _REPORT_TIMEOUT_S
) -> list[dict]:
    """The report's per-object rows, located through the report's own manifest.json.

    Column positions are resolved from manifest.json's ReportSchema rather than assumed, because
    the documented order and the real CSV order have been observed to disagree on the ErrorCode /
    HTTPStatusCode pair; the two columns are told apart by content here.
    """
    base = f"{prefix}/job-{job_id}"
    deadline = time.monotonic() + timeout_s
    manifest = None
    while time.monotonic() < deadline:
        try:
            manifest = json.loads(
                s3.get_object(Bucket=bucket, Key=f"{base}/manifest.json")["Body"].read()
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchKey":
                raise
            time.sleep(5)
    assert manifest, (
        f"no completion report manifest appeared at {base}/manifest.json within {timeout_s}s"
    )
    schema = [c.strip() for c in manifest["ReportSchema"].split(",")]
    results = manifest.get("Results") or []
    assert results, f"the report manifest at {base}/manifest.json lists no Results: {manifest!r}"

    rows = []
    for entry in results:
        raw = s3.get_object(Bucket=bucket, Key=entry["Key"])["Body"].read().decode()
        for row in csv.reader(io.StringIO(raw)):
            if not row:
                continue
            assert len(row) == len(schema), (
                f"report row {row!r} has {len(row)} columns, but ReportSchema declares "
                f"{len(schema)}: {schema!r}"
            )
            by_name = dict(zip(schema, row))
            # The declared ErrorCode/HTTPStatusCode order has been observed to be swapped in the
            # real CSV, so pick whichever of the pair actually holds a numeric status.
            pair = [by_name.get("HTTPStatusCode", ""), by_name.get("ErrorCode", "")]
            numeric = [v for v in pair if v.isdigit()]
            assert len(numeric) == 1, (
                f"neither of the ErrorCode/HTTPStatusCode columns in {row!r} holds exactly one "
                f"numeric status: {pair!r}"
            )
            rows.append(
                {"bucket": by_name["Bucket"], "key": by_name["Key"], "status": numeric[0]}
            )
    return rows


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
                            "s3:GetBucketLocation",
                            "s3:ListBucket",
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
