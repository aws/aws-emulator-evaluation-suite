"""glue-job-bookmark-delta-then-reset-reprocesses-every-file."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "glue-job-bookmark-delta-then-reset-reprocesses-every-file"
GROUP = 'jobs'
SERVICES = ['glue', 's3']

# Five sequential Glue Spark runs at roughly 60-85 s each; every wait below draws from this one
# budget so the check has a hard cap.
_TOTAL_DEADLINE_S = 1500.0

# Five source files with disjoint id ranges, uploaded in two waves, plus a sixth for the
# uncommitted-run arm. Which ids a run sees is the entire subject of this check.
_WAVE1 = {"source/f1.csv": (1, 3), "source/f2.csv": (4, 6), "source/f3.csv": (7, 9)}
_WAVE2 = {"source/f4.csv": (10, 12), "source/f5.csv": (13, 15)}
_WAVE3 = {"source/f6.csv": (16, 18)}

_CTX_NAME = "sim2real_bookmarked_src"

# A real Glue job. The bookmark exists only through GlueContext + transformation_ctx, and it
# advances only at job.commit(). The job reports the exact id SET it read -- not a count -- so
# a run that processed the wrong rows cannot pass by processing the right number of them.
_SCRIPT = b"""import sys
import json
import boto3
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext

a = getResolvedOptions(sys.argv, ['JOB_NAME', 'SOURCE', 'OUT', 'FAIL_BEFORE_COMMIT'])
sc = SparkContext.getOrCreate()
gc = GlueContext(sc)
job = Job(gc)
job.init(a['JOB_NAME'], a)
dyf = gc.create_dynamic_frame.from_options(
    connection_type='s3', format='csv', format_options={'withHeader': True},
    connection_options={'paths': [a['SOURCE']], 'recurse': True},
    transformation_ctx='sim2real_bookmarked_src')
ids = sorted(int(r['id']) for r in dyf.toDF().select('id').collect())
if a['FAIL_BEFORE_COMMIT'] == 'yes':
    raise RuntimeError('SIM2REAL_FORCED_FAILURE_BEFORE_COMMIT ' + json.dumps(ids))
bucket, key = a['OUT'][len('s3://'):].split('/', 1)
boto3.client('s3').put_object(Bucket=bucket, Key=key, Body=json.dumps(ids).encode())
job.commit()
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue job bookmark reads only the delta after a commit, rereads every file after
    ResetJobBookmark, and is not advanced by a run that fails before job.commit().

    Reference: https://docs.aws.amazon.com/glue/latest/dg/monitor-continuations.html
    """
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    budget = time.monotonic() + _TOTAL_DEADLINE_S

    role = ctx.unique_name("sim2real-behav-b5bmrole-")
    job = ctx.unique_name("sim2real-behav-b5bm-")

    bucket = ctx.unique_name("sim2real-behav-b5bm-").lower()

    try:
        _create_bucket(ctx, s3, bucket)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
        s3.put_bucket_tagging(Bucket=bucket,
                              Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
        s3.put_object(Bucket=bucket, Key="scripts/bm.py", Body=_SCRIPT)
        _upload(s3, bucket, _WAVE1)

        role_arn = _create_glue_role(ctx, iam, role, bucket)

        glue.create_job(
            Name=job, Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3",
                     "ScriptLocation": f"s3://{bucket}/scripts/bm.py"},
            GlueVersion="4.0", WorkerType="G.1X", NumberOfWorkers=2, MaxRetries=0,
            ExecutionProperty={"MaxConcurrentRuns": 1},
            DefaultArguments={"--TempDir": f"s3://{bucket}/tmp/",
                              "--job-bookmark-option": "job-bookmark-enable"},
            Tags={"sim2real": CHECK})
        # delete_job also destroys the job's bookmark, so this single registration undoes both.
        ctx.on_cleanup(lambda: _retry_delete(lambda: glue.delete_job(JobName=job),
                                             f"glue job {job}"))

        def go(out_name: str, *, fail: bool = False) -> dict:
            return _run_job_to_terminal(glue, job, {
                "--SOURCE": f"s3://{bucket}/source/",
                "--OUT": f"s3://{bucket}/out/{out_name}.json",
                "--FAIL_BEFORE_COMMIT": "yes" if fail else "no"}, budget=budget)

        # ---------------------------------------------------------------- run 1: the full source
        run1 = go("run1")
        assert run1["JobRunState"] == "SUCCEEDED", (
            f"run 1 ended {run1['JobRunState']!r}: {run1.get('ErrorMessage')!r}"
        )
        assert run1["ExecutionTime"] > 0, (
            f"run 1's ExecutionTime was {run1['ExecutionTime']!r} on a SUCCEEDED run, so no Spark "
            f"compute was billed and nothing actually executed"
        )
        ids1 = _read_ids(s3, bucket, "run1")
        assert ids1 == list(range(1, 10)), (
            f"run 1 read ids {ids1!r}, expected {list(range(1, 10))!r} from f1-f3"
        )

        # ---------------------------------------------------------------- run 2: only the delta
        _upload(s3, bucket, _WAVE2)
        run2 = go("run2")
        assert run2["JobRunState"] == "SUCCEEDED", (
            f"run 2 ended {run2['JobRunState']!r}: {run2.get('ErrorMessage')!r}"
        )
        ids2 = _read_ids(s3, bucket, "run2")
        assert ids2 == list(range(10, 16)), (
            f"run 2 read ids {ids2!r}, expected exactly the delta {list(range(10, 16))!r}; a job "
            f"with no bookmark returns all 15 here"
        )
        assert set(ids2) & set(ids1) == set(), (
            f"run 2's ids overlap run 1's: {sorted(set(ids2) & set(ids1))!r}. The bookmark must "
            f"EXCLUDE what was already consumed, not append to it"
        )

        entry2 = glue.get_job_bookmark(JobName=job)["JobBookmarkEntry"]
        assert entry2["JobName"] == job, (
            f"GetJobBookmark returned an entry for {entry2['JobName']!r}, expected {job!r}"
        )
        assert isinstance(entry2["Run"], int) and entry2["Run"] >= 1, (
            f"the bookmark entry's Run was {entry2['Run']!r} after two successful runs"
        )
        assert _CTX_NAME in (entry2.get("JobBookmark") or ""), (
            f"the persisted JobBookmark does not mention the transformation_ctx {_CTX_NAME!r} "
            f"this check chose; the state must be keyed by that string, not by the job alone. "
            f"JobBookmark was {(entry2.get('JobBookmark') or '')[:300]!r}"
        )

        # ---------------------------------------------------------------- the reset, as an ACT
        reset = glue.reset_job_bookmark(JobName=job)["JobBookmarkEntry"]
        assert reset["JobBookmark"] == "", (
            f"ResetJobBookmark returned JobBookmark {reset['JobBookmark']!r}, expected the empty "
            f"string; the reset must be observable on the control plane, not only by side effect"
        )
        assert "RunId" not in reset, (
            f"the reset entry still carries a RunId ({reset.get('RunId')!r}); a reset bookmark is "
            f"bound to no run"
        )
        assert reset["Run"] > entry2["Run"], (
            f"the reset entry's Run was {reset['Run']!r}, not greater than the pre-reset "
            f"{entry2['Run']!r}; the counter is monotonic across a reset rather than zeroed"
        )

        # -------------------------------------------- run 3: THE assertion no mtime filter passes
        # f1-f3 are older than run 1, so a LastModified filter could never return them again.
        run3 = go("run3")
        assert run3["JobRunState"] == "SUCCEEDED", (
            f"run 3 ended {run3['JobRunState']!r}: {run3.get('ErrorMessage')!r}"
        )
        ids3 = _read_ids(s3, bucket, "run3")
        assert ids3 == list(range(1, 16)), (
            f"after ResetJobBookmark, run 3 read ids {ids3!r} but must read all 15, "
            f"{list(range(1, 16))!r}. f1-f3 are strictly OLDER than run 1, so an implementation "
            f"that filters on LastModified rather than resetting persisted state cannot produce "
            f"this set -- it returns the run-2 delta or nothing"
        )
        assert len(ids3) == len(set(ids3)) == 15, (
            f"run 3 read {len(ids3)} ids with {len(set(ids3))} distinct; a reset means "
            f"reprocess-once, not reprocess-twice: {ids3!r}"
        )

        # ------------------- negative arm: a run that dies before commit consumes nothing at all
        _upload(s3, bucket, _WAVE3)
        run4 = go("run4", fail=True)
        assert run4["JobRunState"] == "FAILED", (
            f"the run whose script raises before job.commit() ended {run4['JobRunState']!r}, "
            f"expected FAILED; ErrorMessage was {run4.get('ErrorMessage')!r}"
        )
        message = run4.get("ErrorMessage") or ""
        assert "SIM2REAL_FORCED_FAILURE_BEFORE_COMMIT" in message, (
            f"the failed run's ErrorMessage does not carry the exception the script raised: "
            f"{message!r}"
        )
        assert _read_ids(s3, bucket, "run4") is None, (
            f"the run that raised before job.commit() still published out/run4.json: "
            f"{_read_ids(s3, bucket, 'run4')!r}"
        )

        run5 = go("run5")
        assert run5["JobRunState"] == "SUCCEEDED", (
            f"run 5 ended {run5['JobRunState']!r}: {run5.get('ErrorMessage')!r}"
        )
        ids5 = _read_ids(s3, bucket, "run5")
        assert ids5 == list(range(16, 19)), (
            f"run 5 read ids {ids5!r}, expected {list(range(16, 19))!r}. Run 4 read that same "
            f"delta and then died before job.commit(), so the bookmark must not have advanced -- "
            f"an implementation that advances at job START leaves run 5 with []"
        )

        entry5 = glue.get_job_bookmark(JobName=job)["JobBookmarkEntry"]
        assert entry5["Run"] > reset["Run"], (
            f"the bookmark Run after run 5 was {entry5['Run']!r}, not greater than the reset's "
            f"{reset['Run']!r}"
        )

        # ------------------------------------------------------------------------ negative space
        out_keys = _list_keys(s3, bucket, "out/")
        expected_out = ["out/run1.json", "out/run2.json", "out/run3.json", "out/run5.json"]
        assert out_keys == expected_out, (
            f"the output prefix holds {out_keys!r}, expected exactly {expected_out!r} -- no "
            f"output from the failed run and nothing extra"
        )
        for key, (low, high) in {**_WAVE1, **_WAVE2, **_WAVE3}.items():
            assert _get_object(s3, bucket, key) == _rows(low, high), (
                f"source object {key!r} was modified by a run; the source must be read-only"
            )
    except BaseException as primary:
        # Inline teardown so a leak is asserted; ctx.on_cleanup is only the failure-path net and
        # cannot affect the verdict.
        try:
            _teardown(glue, s3, iam, jobs=[job], bucket=bucket, roles=[role])
        except Exception as td:  # noqa: BLE001 - the body's failure stays the verdict
            primary.add_note(f"inline teardown also failed: {td!r}")
        raise
    else:
        _teardown(glue, s3, iam, jobs=[job], bucket=bucket, roles=[role])



def _rows(low: int, high: int) -> bytes:
    return ("id\n" + "".join(f"{n}\n" for n in range(low, high + 1))).encode()


def _upload(s3, bucket: str, wave: dict) -> None:
    for key, (low, high) in wave.items():
        s3.put_object(Bucket=bucket, Key=key, Body=_rows(low, high))


def _read_ids(s3, bucket: str, name: str):
    body = _get_object(s3, bucket, f"out/{name}.json")
    return None if body is None else json.loads(body)


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _create_glue_role(ctx, iam, role: str, bucket: str) -> str:
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role),
                                         f"iam role {role}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role, PolicyArn=managed),
        f"detach {managed} from {role}"))
    iam.put_role_policy(RoleName=role, PolicyName="sim2real-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"},
                      {"Effect": "Allow",
                       "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                       "Resource": f"arn:aws:s3:::{bucket}"}]}))
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.delete_role_policy(RoleName=role, PolicyName="sim2real-s3"),
        f"inline policy on {role}"))
    # IAM propagation exposes no condition to poll, so the wait for role-assumability is the
    # bounded retry in _run_job_to_terminal (deadline = the check's own budget), not a sleep here.
    return arn


def _run_job_to_terminal(glue, job: str, arguments: dict, *, budget: float) -> dict:
    """Start the job and poll to a terminal state, retrying the IAM-propagation failure.

    Glue reports "Role ... should be given assume role permissions for Glue Service" as a
    FAILED job *run* a few seconds in, not as a StartJobRun error, and no API reports that
    the role has become assumable -- so the bounded retry has to be on the terminal state.
    ``budget`` is the whole check's monotonic deadline, shared by every run.
    """
    from botocore.exceptions import ClientError

    record: dict = {}
    while time.monotonic() < budget:
        try:
            run_id = glue.start_job_run(JobName=job, Arguments=arguments)["JobRunId"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConcurrentRunsExceededException":
                raise
            time.sleep(5)
            continue
        while time.monotonic() < budget:
            record = glue.get_job_run(JobName=job, RunId=run_id)["JobRun"]
            if record["JobRunState"] in ("SUCCEEDED", "FAILED", "STOPPED", "ERROR",
                                         "TIMEOUT"):
                break
            time.sleep(2)
        if record.get("JobRunState") != "FAILED":
            return record
        if "assume role permissions" not in (record.get("ErrorMessage") or ""):
            return record
        time.sleep(2)
    raise AssertionError(
        f"job {job!r} did not reach a terminal run state inside the check's "
        f"{_TOTAL_DEADLINE_S}s budget; last record was {record!r}")


def _teardown(glue, s3, iam, *, jobs, bucket, roles) -> None:
    """Delete everything and poll each API until it says the resource is gone.

    Raises on anything but the resource already being gone. Children before parents: role
    policies before the role, objects before the bucket.
    """
    from botocore.exceptions import ClientError

    def verify(label: str, delete: Callable[[], Any], probe: Callable[[], Any],
               gone_codes: tuple, *, timeout_s: float = 120.0) -> None:
        try:
            delete()
        except ClientError as err:
            if err.response["Error"]["Code"] not in gone_codes:
                raise
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                probe()
            except ClientError as err:
                if err.response["Error"]["Code"] in gone_codes:
                    return
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the inline teardown found {label} still present "
                                     f"{timeout_s}s after delete")
            time.sleep(2)

    for name in jobs:
        verify(f"glue job {name}", lambda n=name: glue.delete_job(JobName=n),
               lambda n=name: glue.get_job(JobName=n), ("EntityNotFoundException",))
    for role in roles:
        try:
            for policy in iam.list_role_policies(RoleName=role)["PolicyNames"]:
                iam.delete_role_policy(RoleName=role, PolicyName=policy)
            for attached in iam.list_attached_role_policies(
                    RoleName=role)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role, PolicyArn=attached["PolicyArn"])
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise
        verify(f"iam role {role}", lambda r=role: iam.delete_role(RoleName=r),
               lambda r=role: iam.get_role(RoleName=r), ("NoSuchEntity",))
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
    verify(f"s3 bucket {bucket}", lambda: s3.delete_bucket(Bucket=bucket),
           lambda: s3.head_bucket(Bucket=bucket), ("404", "NoSuchBucket"))


def _get_object(s3, bucket: str, key: str):
    from botocore.exceptions import ClientError
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchKey":
            return None
        raise


def _list_keys(s3, bucket: str, prefix: str) -> list:
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _retry_delete(fn: Callable[[], Any], label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions:
    a throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "NoSuchBucket",
            "ResourceNotFoundException", "404")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "InvalidInputException", "RequestLimitExceeded",
                 "ConcurrentRunsExceededException")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)
        except Exception as exc:  # noqa: BLE001 - re-raised
            raise RuntimeError(f"{label}: {type(exc).__name__}: {exc}") from exc


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """The ctx.on_cleanup failure-path net; the inline teardown normally ran first, so an
    already-absent bucket is expected, not a leak."""
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    _retry_delete(lambda: s3.delete_bucket(Bucket=bucket), f"s3 bucket {bucket}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
