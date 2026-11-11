"""batch-job-completion-report-accounts-for-mixed-task-outcomes."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-job-completion-report-accounts-for-mixed-task-outcomes"
GROUP = "state-machine"
SERVICES = ["s3control"]

#: A three-row S3PutObjectTagging job walks New -> Preparing -> Active -> Complete. The sibling
#: run-to-completion check budgets 270s for the same shape; 600s leaves room for a slow Preparing.
_JOB_TERMINAL_TIMEOUT_S = 600.0
#: CreateJob answers BadRequestException until the freshly created batch role is assumable by
#: batchoperations.s3.amazonaws.com. There is no condition to poll, so the retry IS the wait.
_ROLE_READY_TIMEOUT_S = 180.0
#: The completion report is written after the job stops running tasks, which is not the instant
#: DescribeJob first says Complete.
_REPORT_TIMEOUT_S = 240.0
#: Role propagation can also surface after CreateJob succeeds: the job settles into Failed with
#: FailureCode=AccessDenied ("Could not assume the IAM role ..."). Recreate the job on that
#: specific failure until this deadline.
_ROLE_ASSUME_RETRY_TIMEOUT_S = 240.0

_PRESENT_KEYS = ("data/present-one.txt", "data/present-two.txt")
_ABSENT_KEY = "data/absent-by-construction.txt"
_REPORT_PREFIX = "reports"
_REPORT_FORMAT = "Report_CSV_20180820"
_JOB_TAG = {"Key": "sim2real", "Value": "mixed-outcome-report"}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A job with one missing-key row completes with 2 succeeded / 1 failed task, and its completion
    report lists every manifest row with statuses that agree with ProgressSummary."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-jrep-")
    role = ctx.unique_name("sim2real-behav-jreprole-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    # Two rows that CAN succeed and one that cannot. The precondition is asserted, not assumed:
    # the third key must really be absent, or the "one failed task" leg proves nothing.
    for key in _PRESENT_KEYS:
        s3.put_object(Bucket=bucket, Key=key, Body=b"to-be-tagged")
        existing = s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
        assert existing == [], (
            f"{key!r} already carried tags {existing!r} before the job ran, expected none"
        )
    absent_code, absent_code_msg = _error(lambda: s3.head_object(Bucket=bucket, Key=_ABSENT_KEY))
    assert absent_code == "404", (
        f"HeadObject on the deliberately-absent key {_ABSENT_KEY!r} answered {absent_code!r}, "
        "expected a not-found (404); the failed-task leg needs a genuinely missing key"
    )
    absent_code_want = "Not Found"
    assert absent_code_msg == absent_code_want, (
        f"the refusal carried message {absent_code_msg!r}, expected {absent_code_want!r}"
    )

    manifest_rows = [(bucket, key) for key in (*_PRESENT_KEYS, _ABSENT_KEY)]
    manifest_body = "".join(f"{b},{k}\n" for b, k in manifest_rows).encode()
    manifest_etag = s3.put_object(
        Bucket=bucket, Key="manifest.csv", Body=manifest_body
    )["ETag"].strip('"')
    role_arn = _batch_role(ctx, iam, role, bucket)

    job, job_ids = _create_job_surviving_role_propagation(
        ctx, s3c, account, bucket, manifest_etag, role_arn
    )
    for jid in job_ids:
        ctx.on_cleanup(lambda jid=jid: _cancel_job(s3c, account, jid))

    assert job["Status"] == "Complete", (
        f"the job settled into {job['Status']!r} (FailureReasons "
        f"{job.get('FailureReasons')!r}), expected Complete: one unsatisfiable manifest row is a "
        "TASK failure, not a JOB failure"
    )
    summary = job["ProgressSummary"]
    assert summary["TotalNumberOfTasks"] == len(manifest_rows), (
        f"ProgressSummary reports TotalNumberOfTasks={summary['TotalNumberOfTasks']!r}, "
        f"expected {len(manifest_rows)} — one task per manifest row"
    )
    assert summary["NumberOfTasksSucceeded"] == len(_PRESENT_KEYS), (
        f"ProgressSummary reports NumberOfTasksSucceeded="
        f"{summary['NumberOfTasksSucceeded']!r}, expected {len(_PRESENT_KEYS)}"
    )
    assert summary["NumberOfTasksFailed"] == 1, (
        f"ProgressSummary reports NumberOfTasksFailed={summary['NumberOfTasksFailed']!r}, "
        "expected exactly 1 (the row naming the absent key)"
    )

    # Independent reads at the destination: the operation really ran on the two present objects
    # and really did not conjure the third.
    expected_tags = {_JOB_TAG["Key"]: _JOB_TAG["Value"]}
    for key in _PRESENT_KEYS:
        got = {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]}
        assert got == expected_tags, (
            f"after the job {key!r} carried tags {got!r}, expected the job's single tag "
            f"{expected_tags!r}"
        )
    still_absent, still_absent_msg = _error(lambda: s3.head_object(Bucket=bucket, Key=_ABSENT_KEY))
    assert still_absent == "404", (
        f"HeadObject on {_ABSENT_KEY!r} answered {still_absent!r} after the job, expected it to "
        "still be absent — the job must not have created the object it failed on"
    )
    still_absent_want = "Not Found"
    assert still_absent_msg == still_absent_want, (
        f"the refusal carried message {still_absent_msg!r}, expected {still_absent_want!r}"
    )

    # ===== the terminal read: the completion report, an artifact in S3, not a job field =====
    report_root = f"{_REPORT_PREFIX}/job-{job['JobId']}"
    report_manifest = json.loads(
        _poll_object_bytes(s3, bucket, f"{report_root}/manifest.json").decode()
    )
    assert report_manifest["Format"] == _REPORT_FORMAT, (
        f"the report manifest declares Format={report_manifest['Format']!r}, expected the "
        f"{_REPORT_FORMAT!r} the job requested"
    )
    results = report_manifest["Results"]
    assert results, (
        f"the report manifest at {report_root}/manifest.json lists no Results: "
        f"{report_manifest!r}"
    )
    for entry in results:
        assert entry["Bucket"] == bucket, (
            f"a report Results entry names bucket {entry['Bucket']!r}, expected the report "
            f"destination {bucket!r}"
        )

    listed = _list_keys(s3, bucket, f"{report_root}/results/")
    csv_keys = sorted(k for k in listed if k.endswith(".csv"))
    assert len(csv_keys) == len(results), (
        f"{len(csv_keys)} result CSVs are under {report_root}/results/ ({csv_keys!r}) but the "
        f"report manifest lists {len(results)} Results entries"
    )

    rows: list[list[str]] = []
    for entry in results:
        matches = [k for k in csv_keys if k.endswith(entry["Key"].lstrip("/"))]
        assert len(matches) == 1, (
            f"report manifest Results key {entry['Key']!r} matched {matches!r} of the listed "
            f"result objects {csv_keys!r}, expected exactly one"
        )
        raw = s3.get_object(Bucket=bucket, Key=matches[0])["Body"].read()
        digest = hashlib.md5(raw).hexdigest()  # noqa: S324 - AWS reports md5, not a security use
        assert digest == entry["MD5Checksum"], (
            f"the report manifest claims MD5Checksum={entry['MD5Checksum']!r} for "
            f"{matches[0]!r} but the {len(raw)} bytes actually stored hash to {digest!r}"
        )
        # Fields are stripped once, here, so every column comparison below sees the same text.
        rows.extend(
            [field.strip() for field in r]
            for r in csv.reader(io.StringIO(raw.decode()))
            if any(field.strip() for field in r)
        )

    schema = [c.strip() for c in report_manifest["ReportSchema"].split(",")]
    for row in rows:
        assert len(row) == len(schema), (
            f"report row {row!r} has {len(row)} fields but the declared ReportSchema "
            f"{schema!r} has {len(schema)}"
        )

    # Columns are located BY CONTENT because the CSV order disagrees with the declared
    # ReportSchema (asserted at the end). Locating them is itself an assertion.
    key_set = {k for _, k in manifest_rows}
    key_col = _sole_column(
        rows, lambda values: values == key_set,
        f"the column whose value set is exactly the manifest keys {sorted(key_set)!r}",
    )
    status_col = _sole_column(
        rows, lambda values: values and all(v.isdigit() and len(v) == 3 for v in values),
        "the column holding a 3-digit HTTP status on every row",
    )
    bucket_col = _sole_column(
        rows, lambda values: values == {bucket},
        f"the column naming the source bucket {bucket!r} on every row",
    )

    reported = sorted((row[bucket_col], row[key_col]) for row in rows)
    assert reported == sorted(manifest_rows), (
        f"the completion report accounts for {reported!r}, expected exactly the manifest rows "
        f"{sorted(manifest_rows)!r} — one row per task, no more and no fewer"
    )

    ok = [row for row in rows if row[status_col] == "200"]
    bad = [row for row in rows if row[status_col] != "200"]
    assert len(ok) == summary["NumberOfTasksSucceeded"], (
        f"the report carries {len(ok)} rows with HTTP 200 but ProgressSummary claims "
        f"NumberOfTasksSucceeded={summary['NumberOfTasksSucceeded']!r}"
    )
    assert len(bad) == summary["NumberOfTasksFailed"], (
        f"the report carries {len(bad)} non-200 rows but ProgressSummary claims "
        f"NumberOfTasksFailed={summary['NumberOfTasksFailed']!r}"
    )
    assert {row[key_col] for row in bad} == {_ABSENT_KEY}, (
        f"the non-200 report rows name keys {sorted(row[key_col] for row in bad)!r}, expected "
        f"only the absent key {_ABSENT_KEY!r}"
    )
    assert all(400 <= int(row[status_col]) <= 499 for row in bad), (
        f"the failed task reported HTTP {[row[status_col] for row in bad]!r}, expected a 4xx "
        "client error for a key that does not exist"
    )

    # TaskStatus is located by the report's OWN declared schema rather than by content: both doc
    # sources agree on its position, and ErrorCode/ResultMessage would also split the rows in two,
    # so a content search cannot be made unambiguous here.
    positions = {name: i for i, name in enumerate(schema)}
    assert "TaskStatus" in positions, (
        f"the report's declared ReportSchema {schema!r} has no TaskStatus column"
    )
    task_col = positions["TaskStatus"]
    ok_status = {row[task_col] for row in ok}
    bad_status = {row[task_col] for row in bad}
    assert len(ok_status) == 1 and len(bad_status) == 1 and ok_status != bad_status, (
        f"the report's TaskStatus column reads {sorted(ok_status)!r} for the HTTP-200 rows and "
        f"{sorted(bad_status)!r} for the non-200 rows; expected exactly one distinct value each, "
        "and the two must differ"
    )

    # AWS quirk: the CSV does not match its own ReportSchema. Key, Bucket and TaskStatus are where
    # ReportSchema says, but ErrorCode and HTTPStatusCode are swapped. ErrorCode is located by
    # content (empty on succeeded rows, non-empty on failed ones), so the swap is measured.
    error_candidates = [
        c for c in range(len(schema))
        if c not in (key_col, status_col, bucket_col)
        and all(row[c] == "" for row in ok)
        and all(row[c] != "" for row in bad)
    ]
    assert len(error_candidates) == 1, (
        f"looked for the column holding an error code (empty for succeeded rows, non-empty for "
        f"failed rows) among {[c for c in range(len(schema)) if c not in (key_col, status_col, bucket_col)]!r} "
        f"and found {error_candidates!r}, expected exactly one. Rows: {rows!r}"
    )
    error_col = error_candidates[0]

    assert (positions.get("Key"), positions.get("Bucket")) == (key_col, bucket_col), (
        f"the report CSV disagrees with its own declared ReportSchema {schema!r} on Key/Bucket: "
        f"the keys are actually in column {key_col}, the bucket in {bucket_col}"
    )
    assert positions.get("HTTPStatusCode") == error_col and positions.get("ErrorCode") == status_col, (
        f"expected the declared ReportSchema {schema!r} to mislabel HTTPStatusCode and ErrorCode "
        f"— the real HTTP status is in column {status_col} and the real error code is in column "
        f"{error_col}, so a correct-but-undeclared CSV would need ReportSchema's HTTPStatusCode "
        f"at {error_col} and ErrorCode at {status_col}; got HTTPStatusCode declared at "
        f"{positions.get('HTTPStatusCode')!r} and ErrorCode at {positions.get('ErrorCode')!r}"
    )


# ===== helpers =====

def _sole_column(rows, predicate, description: str) -> int:
    """The single column index whose value set satisfies ``predicate``. Raises otherwise."""
    assert rows, f"there are no report rows, so {description} cannot be located"
    width = len(rows[0])
    hits = [col for col in range(width) if predicate({row[col] for row in rows})]
    assert len(hits) == 1, (
        f"looked for {description} and found columns {hits!r} of {width}; expected exactly one. "
        f"Rows: {rows!r}"
    )
    return hits[0]


def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _is_role_not_ready(job: dict) -> bool:
    """Whether ``job``'s FailureReasons name the batch role as not yet assumable.

    The same underlying IAM-propagation delay _create_job retries on via CreateJob's own
    BadRequestException, seen here instead as a settled job.
    """
    for reason in job.get("FailureReasons") or []:
        if reason.get("FailureCode") == "AccessDenied" and "assume the iam role" in (
            reason.get("FailureReason") or ""
        ).lower():
            return True
    return False


def _create_job_surviving_role_propagation(
    ctx, s3c, account: str, bucket: str, manifest_etag: str, role_arn: str
) -> tuple[dict, list[str]]:
    """Create the job and wait for a terminal status, recreating it if the role was not ready.

    Returns the terminal job dict and every JobId created along the way, so the caller can clean
    up each one (only the last is expected to still exist, but a mid-retry job may not have been
    cancelled by anything else).
    """
    deadline = time.monotonic() + _ROLE_ASSUME_RETRY_TIMEOUT_S
    job_ids: list[str] = []
    while True:
        job_id = _create_job(ctx, s3c, account, bucket, manifest_etag, role_arn)
        job_ids.append(job_id)
        job = _poll_terminal(s3c, account, job_id)
        if job["Status"] == "Failed" and _is_role_not_ready(job) and time.monotonic() < deadline:
            time.sleep(5)
            continue
        return job, job_ids


def _create_job(ctx, s3c, account: str, bucket: str, manifest_etag: str, role_arn: str) -> str:
    """CreateJob, retrying only the role-not-yet-assumable rejection, until the deadline."""
    deadline = time.monotonic() + _ROLE_READY_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            return s3c.create_job(
                AccountId=account,
                ConfirmationRequired=False,
                Operation={"S3PutObjectTagging": {"TagSet": [_JOB_TAG]}},
                Report={
                    "Bucket": f"arn:aws:s3:::{bucket}",
                    "Format": _REPORT_FORMAT,
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
                        "ObjectArn": f"arn:aws:s3:::{bucket}/manifest.csv",
                        "ETag": manifest_etag,
                    },
                },
                Priority=10,
                RoleArn=role_arn,
                Description="sim2real-behav mixed-outcome completion report",
                Tags=[{"Key": "sim2real", "Value": ctx.unique_name("jrep-")}],
            )["JobId"]
        except ClientError as exc:
            last = exc.response["Error"]
            if last["Code"] != "BadRequestException":
                raise
            time.sleep(5)
    raise AssertionError(
        f"CreateJob never succeeded within {_ROLE_READY_TIMEOUT_S}s; last error {last!r} — the "
        "batch role did not become assumable"
    )


def _poll_terminal(s3c, account: str, job_id: str) -> dict:
    """DescribeJob until the job is terminal. Raises on timeout; never returns a transient state."""
    deadline = time.monotonic() + _JOB_TERMINAL_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]
        if last["Status"] in ("Complete", "Failed", "Cancelled"):
            return last
        time.sleep(3)
    raise AssertionError(
        f"job {job_id} was still {last['Status']!r} after {_JOB_TERMINAL_TIMEOUT_S}s "
        f"(ProgressSummary {last.get('ProgressSummary')!r}); expected a terminal status"
    )


def _poll_object_bytes(s3, bucket: str, key: str) -> bytes:
    """Wait for ``key`` to exist and return its bytes. Raises on timeout, never returns empty."""
    deadline = time.monotonic() + _REPORT_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            time.sleep(5)
    raise AssertionError(
        f"s3://{bucket}/{key} never appeared within {_REPORT_TIMEOUT_S}s of the job completing "
        f"(last error {last!r}); a completed job with Report.Enabled must write its report"
    )


def _list_keys(s3, bucket: str, prefix: str) -> list:
    out: list = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(o["Key"] for o in page.get("Contents", []))
    return out


def _cancel_job(s3c, account: str, job_id: str) -> None:
    try:
        status = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]["Status"]
        if status in ("New", "Preparing", "Suspended", "Ready", "Active", "Paused"):
            s3c.update_job_status(
                AccountId=account, JobId=job_id, RequestedJobStatus="Cancelled",
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


def _batch_role(ctx, iam, role: str, bucket: str) -> str:
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
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    iam.put_role_policy(
        RoleName=role, PolicyName="batch",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject", "s3:PutObjectTagging", "s3:GetObjectTagging",
                        "s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket",
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }),
    )
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
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )


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
