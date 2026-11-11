"""spark-write-outside-execution-role-prefix-is-denied."""
from __future__ import annotations

import gzip
import json
import time
import uuid

from behavioral_harness import tags

CHECK = "spark-write-outside-execution-role-prefix-is-denied"
GROUP = "negative-classes"
SERVICES = ["emr-serverless"]

RELEASE_LABEL = "emr-7.9.0"

# Declared deadlines: three cold-ish Spark job runs on one application take well over 300 s.
_JOB_BUDGET_S = 900.0
_LOG_BUDGET_S = 420.0
_APP_TEARDOWN_BUDGET_S = 420.0

# The single job, run three times against two different output prefixes (the third replays the
# second's own args after the role's policy is widened).
_SPARK_JOB = '''\
import sys

from pyspark.sql import SparkSession

out_uri, nonce = sys.argv[1:3]
spark = SparkSession.builder.appName("sim2real-emrs-prefix-scope").getOrCreate()
spark.createDataFrame([(1, nonce)], ["id", "marker"]).coalesce(1) \\
    .write.mode("overwrite").option("header", False).csv(out_uri)
spark.stop()
'''


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    # Not a region pin: CreateBucket rejects a LocationConstraint that names us-east-1 itself, so the
    # comparison is against that one literal API quirk, not against ctx.region's actual value.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _purge_and_delete() -> None:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_purge_and_delete)


_ROLE_POLICY_NAME = "sim2real-prefix-scope"


def _write_scope_policy(iam, role_name: str, bucket: str, write_prefixes: list[str]) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
                "Resource": [f"arn:aws:s3:::{bucket}/{p}*" for p in write_prefixes],
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_ROLE_POLICY_NAME, PolicyDocument=json.dumps(policy)
    )


def _create_prefix_scoped_role(ctx, iam, bucket: str, allowed_prefix: str) -> tuple[str, str]:
    """An execution role that may READ the whole bucket but may only WRITE under one prefix."""
    role_name = ctx.unique_name("sim2real-emrs-scope-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "emr-serverless.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    _write_scope_policy(iam, role_name, bucket, [allowed_prefix])
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_ROLE_POLICY_NAME)
    )
    return role_arn, role_name


def _start_job_run_with_retry(ctx, emrs, app_id: str, role_arn: str, job_driver: dict) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_job_run(
                applicationId=app_id,
                clientToken=ctx.unique_name("sim2real-emrs-tok-"),
                executionRoleArn=role_arn,
                jobDriver=job_driver,
            )["jobRunId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"StartJobRun never succeeded after IAM propagation wait: {last_exc}")


def _await_job_run(emrs, app_id: str, job_run_id: str, budget_s: float) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCELLED"}
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_job_run(applicationId=app_id, jobRunId=job_run_id)["jobRun"]
        if last["state"] in terminal:
            return last
        time.sleep(2)
    raise AssertionError(
        f"job run {job_run_id} never reached a terminal state within {budget_s}s "
        f"(last state {last!r})"
    )


_ROLE_NOT_READY = "Could not assume runtime role"
_ACCESS_STILL_PROPAGATING = "AccessDenied"


def _run_job_to_terminal(ctx, emrs, app_id: str, role_arn: str, job_driver: dict,
                         budget_s: float, *, retry_marker: str = _ROLE_NOT_READY,
                         max_attempts: int = 5, retry_wait_s: float = 30.0) -> tuple[str, dict]:
    """Start a job run and wait for a terminal state, retrying ONLY the named IAM-propagation
    failure. Two call sites, two different propagation delays that share the same shape:

    - the DEFAULT (a freshly created execution role is accepted by StartJobRun -- the control plane
      -- a minute or more before EMR Serverless can actually assume it; the symptom is a FAILED job
      run whose stateDetails reads "Could not assume runtime role ...").
    - the RESTORE leg (an inline policy just widened on an ALREADY-assumable role is also eventually
      consistent; the symptom there is a FAILED job run whose stateDetails names AccessDenied for
      the very key the widened statement now grants).

    No API exposes a condition to poll for either, so this bounded retry IS the wait. Any other
    failure is returned unchanged for the caller to assert on, so this never masks a real refusal.
    """
    last = None
    for _ in range(max_attempts):
        job_run_id = _start_job_run_with_retry(ctx, emrs, app_id, role_arn, job_driver)
        last = _await_job_run(emrs, app_id, job_run_id, budget_s)
        if not (last["state"] == "FAILED"
                and retry_marker in (last.get("stateDetails") or "")):
            return job_run_id, last
        time.sleep(retry_wait_s)
    raise AssertionError(
        f"execution role {role_arn} never cleared {retry_marker!r} after {max_attempts} job runs: "
        f"{last!r}"
    )


def _teardown_application(emrs, app_id: str, budget_s: float) -> None:
    """Stop then delete the application, raising if it does not reach STOPPED within budget_s.

    Runs inline in the check body so a slow stop+delete is bounded by the check's own budget.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + budget_s
    try:
        emrs.stop_application(applicationId=app_id)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        # An application already stopping, stopped or terminated is refused; the poll settles it.
        if code != "ValidationException":
            raise
    while time.monotonic() < deadline:
        try:
            state = emrs.get_application(applicationId=app_id)["application"]["state"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if state == "TERMINATED":
            return
        if state in ("CREATED", "STOPPED"):
            break
        time.sleep(2)
    else:
        raise AssertionError(f"application {app_id} did not reach STOPPED within {budget_s}s")
    emrs.delete_application(applicationId=app_id)


def _list_keys(s3, bucket: str, prefix: str) -> list[str]:
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(out)


def _await_driver_stderr(s3, bucket: str, log_prefix: str, app_id: str, job_run_id: str,
                         budget_s: float) -> tuple[str, bytes]:
    """Poll for the job run's own SPARK_DRIVER/stderr.gz under the configured log destination."""
    want = f"{log_prefix}applications/{app_id}/jobs/{job_run_id}/SPARK_DRIVER/stderr.gz"
    deadline = time.monotonic() + budget_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        seen = _list_keys(s3, bucket, f"{log_prefix}applications/{app_id}/jobs/{job_run_id}/")
        if want in seen:
            body = s3.get_object(Bucket=bucket, Key=want)["Body"].read()
            if body:
                return want, body
        time.sleep(2)
    raise AssertionError(
        f"no non-empty {want!r} appeared within {budget_s}s; keys under the job's log prefix were "
        f"{seen!r}"
    )


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Spark job's S3 writes are bound by its execution role's prefix-scoped grant in the data
    plane: a write under `allowed/` succeeds, the same write under `denied/` fails with AccessDenied
    and leaves `denied/` empty, and it succeeds once the role's policy is widened to `denied/*`."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")

    bucket = ctx.unique_name("sim2real-emrs-scope-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    nonce = f"sim2real-{uuid.uuid4().hex}"
    log_prefix = "allowed/logs/"
    s3.put_object(Bucket=bucket, Key="job/write.py", Body=_SPARK_JOB.encode("utf-8"))

    role_arn, role_name = _create_prefix_scoped_role(ctx, iam, bucket, "allowed/")

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-scope-app-"),
        releaseLabel=RELEASE_LABEL,
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        monitoringConfiguration={
            "s3MonitoringConfiguration": {"logUri": f"s3://{bucket}/{log_prefix}"}
        },
    )["applicationId"]
    # Failure-path net only; the verified teardown is inline in the finally below.
    ctx.on_cleanup(lambda: _teardown_application(emrs, app_id, 120.0))

    try:
        def _driver(out_uri: str) -> dict:
            return {
                "sparkSubmit": {
                    "entryPoint": f"s3://{bucket}/job/write.py",
                    "entryPointArguments": [out_uri, nonce],
                    "sparkSubmitParameters": (
                        "--conf spark.driver.cores=1 --conf spark.driver.memory=2g "
                        "--conf spark.executor.cores=1 --conf spark.executor.memory=2g "
                        "--conf spark.executor.instances=1"
                    ),
                }
            }

        # ---------- positive control: the ALLOWED prefix ----------
        ok_run, ok_final = _run_job_to_terminal(
            ctx, emrs, app_id, role_arn, _driver(f"s3://{bucket}/allowed/out/"), _JOB_BUDGET_S
        )
        assert ok_final["state"] == "SUCCESS", (
            f"control run {ok_run} writing to the ALLOWED prefix ended {ok_final['state']!r}: "
            f"{ok_final.get('stateDetails')!r} — the fixture itself is broken, so the denial below "
            f"would prove nothing"
        )
        ok_keys = _list_keys(s3, bucket, "allowed/out/")
        ok_parts = [k for k in ok_keys if "/part-" in k]
        assert len(ok_parts) == 1, (
            f"control run wrote {len(ok_parts)} part files, expected exactly 1; keys were "
            f"{ok_keys!r}"
        )
        ok_body = s3.get_object(Bucket=bucket, Key=ok_parts[0])["Body"].read().decode("utf-8")
        assert ok_body.strip() == f"1,{nonce}", (
            f"control object {ok_parts[0]!r} contains {ok_body.strip()!r}, expected "
            f"{'1,' + nonce!r} — this run's own nonce"
        )

        # ---------- break exactly one thing: the output prefix ----------
        bad_run, bad_final = _run_job_to_terminal(
            ctx, emrs, app_id, role_arn, _driver(f"s3://{bucket}/denied/out/"), _JOB_BUDGET_S
        )
        assert bad_final["state"] == "FAILED", (
            f"run {bad_run} writing OUTSIDE the execution role's PutObject prefix ended "
            f"{bad_final['state']!r}, expected FAILED — the backend accepted a write real AWS "
            f"refuses ({bad_final.get('stateDetails')!r})"
        )

        # effect-absent: nothing at all under the denied prefix
        denied_keys = _list_keys(s3, bucket, "denied/")
        assert denied_keys == [], (
            f"the denied prefix is not empty: {denied_keys!r} — the write was refused but data "
            f"landed anyway"
        )

        # the refusal is legible where an operator would look for it
        log_key, log_gz = _await_driver_stderr(
            s3, bucket, log_prefix, app_id, bad_run, _LOG_BUDGET_S
        )
        assert log_gz[:2] == b"\x1f\x8b", (
            f"{log_key!r} does not start with the gzip magic, got {log_gz[:2]!r}"
        )
        stderr_text = gzip.decompress(log_gz).decode("utf-8", errors="replace")
        assert "AccessDenied" in stderr_text, (
            f"the driver log for the denied run does not name AccessDenied "
            f"(tail: {stderr_text[-600:]!r})"
        )
        assert "Status Code: 403" in stderr_text, (
            f"the driver log for the denied run does not carry HTTP status 403 "
            f"(tail: {stderr_text[-600:]!r})"
        )
        assert "denied/out" in stderr_text, (
            f"the driver log does not name the denied output path, so the 403 cannot be attributed "
            f"to it (tail: {stderr_text[-600:]!r})"
        )

        # the denial was PREFIX-scoped, not a blanket credential failure: logs under `allowed/`
        # were written by the very same role during the very same failing run.
        assert log_key.startswith(log_prefix), (
            f"driver log {log_key!r} is not under the configured allowed log prefix "
            f"{log_prefix!r}"
        )

        # control still intact after the failure
        still_there = s3.get_object(
            Bucket=bucket, Key=ok_parts[0]
        )["Body"].read().decode("utf-8").strip()
        assert still_there == f"1,{nonce}", (
            f"after the denied run, the control object reads {still_there!r} instead of "
            f"{'1,' + nonce!r}"
        )

        # ---------- restore: widen the SAME role's policy, replay the IDENTICAL call ----------
        _write_scope_policy(iam, role_name, bucket, ["allowed/", "denied/"])
        restored_run, restored_final = _run_job_to_terminal(
            ctx, emrs, app_id, role_arn, _driver(f"s3://{bucket}/denied/out/"), _JOB_BUDGET_S,
            retry_marker=_ACCESS_STILL_PROPAGATING, max_attempts=4, retry_wait_s=20.0,
        )
        assert restored_final["state"] == "SUCCESS", (
            f"run {restored_run} writing to `denied/out/` after widening the policy to grant it "
            f"ended {restored_final['state']!r}: {restored_final.get('stateDetails')!r} — the "
            f"earlier refusal must have been the policy scope, not something else about the key"
        )
        restored_keys = [k for k in _list_keys(s3, bucket, "denied/out/") if "/part-" in k]
        assert len(restored_keys) == 1, (
            f"restored run wrote {len(restored_keys)} part files under denied/out/, expected "
            f"exactly 1; keys were {restored_keys!r}"
        )
        restored_body = s3.get_object(
            Bucket=bucket, Key=restored_keys[0]
        )["Body"].read().decode("utf-8").strip()
        assert restored_body == f"1,{nonce}", (
            f"restored object {restored_keys[0]!r} contains {restored_body!r}, expected "
            f"{'1,' + nonce!r} — this run's own nonce"
        )
    finally:
        _teardown_application(emrs, app_id, _APP_TEARDOWN_BUDGET_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
