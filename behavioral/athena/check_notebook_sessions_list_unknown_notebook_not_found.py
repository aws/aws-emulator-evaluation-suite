"""notebook-sessions-list-unknown-notebook-not-found."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notebook-sessions-list-unknown-notebook-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListNotebookSessions on a well-formed unknown notebook id fails with InvalidRequestException
    (not the documented ResourceNotFoundException), while a real notebook with no sessions returns
    an empty list."""
    athena = ctx.client("athena")
    bogus_notebook_id = str(uuid.uuid4())

    got = _error(lambda: athena.list_notebook_sessions(NotebookId=bogus_notebook_id))
    expected = ("InvalidRequestException", f"Notebook {bogus_notebook_id} was not found")
    assert got == expected, f"expected an unknown NotebookId to raise {expected}, got {got}"

    # Positive control: the identical call against a real notebook succeeds.
    setup = _setup_spark_workgroup(ctx)
    notebook_id = athena.create_notebook(
        WorkGroup=setup["workgroup"], Name=ctx.unique_name("sim2real-athena-nb-")
    )["NotebookId"]
    ctx.on_cleanup(lambda: _safe_delete_notebook(athena, notebook_id))

    sessions = athena.list_notebook_sessions(NotebookId=notebook_id)["NotebookSessionsList"]
    assert sessions == [], f"expected no sessions on a freshly-created notebook, got {sessions}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_notebook(athena: Any, notebook_id: str) -> None:
    try:
        athena.delete_notebook(NotebookId=notebook_id)
    except ClientError as exc:
        if not _not_found(exc):
            raise


def _not_found(exc: ClientError) -> bool:
    """Athena reports a missing resource as ResourceNotFoundException or an InvalidRequestException saying so."""
    err = exc.response["Error"]
    msg = err.get("Message", "")
    return err.get("Code") == "ResourceNotFoundException" or (
        err.get("Code") == "InvalidRequestException" and ("not found" in msg or "does not exist" in msg)
    )


_SPARK_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
    "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
]


def _setup_spark_workgroup(ctx) -> dict[str, str]:
    athena = ctx.client("athena")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "athena.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    role_arn = role["Role"]["Arn"]

    def _cleanup_role() -> None:
        for policy_arn in _SPARK_POLICIES:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    for policy_arn in _SPARK_POLICIES:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    bucket_name = ctx.unique_name("sim2real-athena-spark-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup_bucket() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)

    # Newly created IAM roles can take a few seconds to be assumable by Athena
    # (cross-service IAM propagation); retry CreateWorkGroup until it accepts the
    # ExecutionRole or the bounded window elapses.
    workgroup = ctx.unique_name("sim2real-spark-wg-")
    configuration = {
        "ExecutionRole": role_arn,
        "EngineVersion": {"SelectedEngineVersion": _pick_spark_engine_version(athena)},
        "ResultConfiguration": {"OutputLocation": f"s3://{bucket_name}/"},
    }
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            athena.create_work_group(Name=workgroup, Configuration=configuration)
            created = True
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(5.0)
    if not created:
        raise AssertionError(f"CreateWorkGroup never succeeded within 60s: {last_exc}")

    def _cleanup_wg() -> None:
        try:
            athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
        except ClientError as exc:
            if not _not_found(exc):
                raise

    ctx.on_cleanup(_cleanup_wg)

    return {"workgroup": workgroup, "bucket": bucket_name, "role_arn": role_arn}


def _pick_spark_engine_version(athena) -> str:
    versions = athena.list_engine_versions()["EngineVersions"]
    # Only "PySpark engine version N" supports notebooks; CreateNotebook rejects a workgroup
    # on an "Apache Spark version N.N" engine.
    for v in versions:
        if "pyspark" in v["SelectedEngineVersion"].lower():
            return v["SelectedEngineVersion"]
    for v in versions:
        if "spark" in v["SelectedEngineVersion"].lower():
            return v["SelectedEngineVersion"]
    raise AssertionError(f"no Spark engine version offered by ListEngineVersions: {versions}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
