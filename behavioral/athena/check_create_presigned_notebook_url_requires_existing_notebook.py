"""create-presigned-notebook-url-requires-existing-notebook."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-presigned-notebook-url-requires-existing-notebook"
GROUP = "server-side"
SERVICES = ["athena"]

@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePresignedNotebookUrl returns a live NotebookUrl/AuthToken for a session bound to an
    active notebook, and InvalidRequestException (not ResourceNotFoundException) once that
    session is terminated or for a SessionId that was never created."""
    athena = ctx.client("athena")
    role_arn = _iam_role_for_spark(ctx)
    workgroup = _spark_workgroup(ctx, role_arn)

    notebook_id = athena.create_notebook(
        WorkGroup=workgroup, Name=ctx.unique_name("sim2real-nb-")
    )["NotebookId"]
    ctx.on_cleanup(lambda: _safe_delete_notebook(ctx, notebook_id))

    session_id = _start_spark_session(ctx, workgroup, role_arn, notebook_id=notebook_id)

    presigned = athena.create_presigned_notebook_url(SessionId=session_id)
    assert presigned["NotebookUrl"].startswith("http")
    assert len(presigned["AuthToken"]) > 0
    # Real AWS returns the token lifetime in seconds here, not the epoch timestamp the API
    # reference describes.
    assert presigned["AuthTokenExpirationTime"] == 600, presigned["AuthTokenExpirationTime"]

    athena.terminate_session(SessionId=session_id)
    terminated = _poll_session_state(ctx, session_id, {"TERMINATED", "FAILED"}, timeout_s=180)
    assert terminated == "TERMINATED", f"session {session_id} ended at {terminated!r}, not TERMINATED"
    code, message = _error(lambda: athena.create_presigned_notebook_url(SessionId=session_id))
    assert code == "InvalidRequestException", code
    assert message == "Invalid Request", message

    unknown_session_id = str(uuid.uuid4())
    code, message = _error(lambda: athena.create_presigned_notebook_url(SessionId=unknown_session_id))
    assert code == "InvalidRequestException", code
    assert message == "Not authorized to make this request.", message


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what real AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _iam_role_for_spark(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "athena.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policies = [
        "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    ]
    for arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _spark_workgroup(ctx, role_arn):
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-spark-wg-")
    # Real AWS requires ResultConfiguration on CreateWorkGroup even for a Spark
    # (interactive) workgroup.
    bucket = _s3_output_bucket(ctx)
    athena.create_work_group(
        Name=name,
        Configuration={
            "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
            "ExecutionRole": role_arn,
            "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/athena-spark-results/"},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    return name


def _s3_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    return bucket


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_session_state(ctx, session_id, target_states, timeout_s, interval_s=6.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    return state


def _start_spark_session(ctx, workgroup, role_arn, notebook_id=None, timeout_s=480):
    athena = ctx.client("athena")
    engine_config = {"CoordinatorDpuSize": 1, "MaxConcurrentDpus": 3, "DefaultExecutorDpuSize": 1}
    kwargs = {}
    if notebook_id:
        engine_config["AdditionalConfigs"] = {"NotebookId": notebook_id}
        kwargs["NotebookVersion"] = "Athena notebook version 1"

    # IAM role propagation is eventually consistent; retry StartSession on a
    # transient ClientError (the role not yet visible to Athena) until it is usable.
    session_id = None
    last_error = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            session_id = athena.start_session(
                WorkGroup=workgroup, ExecutionRole=role_arn,
                EngineConfiguration=engine_config,
                **kwargs,
            )["SessionId"]
            break
        except ClientError as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ("dpu", "capacity", "quota", "limit")):
                raise AssertionError(f"Spark session capacity unavailable: {exc}") from exc
            last_error = exc
            time.sleep(2)
    if session_id is None:
        raise AssertionError(f"StartSession never succeeded (IAM role propagation?): {last_error}")
    ctx.on_cleanup(lambda: _safe_terminate(ctx, session_id))
    state = _poll_session_state(ctx, session_id, {"IDLE", "FAILED", "DEGRADED"}, timeout_s)
    if state != "IDLE":
        raise AssertionError(f"session {session_id} never reached IDLE, ended at {state!r}")
    return session_id


def _safe_terminate(ctx, session_id):
    athena = ctx.client("athena")
    try:
        athena.terminate_session(SessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_notebook(ctx, notebook_id):
    athena = ctx.client("athena")
    try:
        athena.delete_notebook(NotebookId=notebook_id)
    except ClientError as exc:
        # Only an unknown notebook ("Notebook ... was not found") means nothing is left.
        if "not found" not in exc.response["Error"].get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
