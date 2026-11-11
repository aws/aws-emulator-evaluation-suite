"""create-notebook-on-sql-workgroup-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-notebook-on-sql-workgroup-rejected"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNotebook against a plain Athena SQL workgroup is rejected with
    InvalidRequestException and creates nothing, while the identical call against a
    Spark-enabled workgroup succeeds (positive control)."""
    athena = ctx.client("athena")

    sql_wg = ctx.unique_name("sim2real-sql-wg-")
    athena.create_work_group(Name=sql_wg)
    ctx.on_cleanup(lambda: _safe_delete_wg(athena, sql_wg))

    not_spark = "Workgroup EngineVersion is not Spark."
    code, message = _error(
        lambda: athena.create_notebook(WorkGroup=sql_wg, Name=ctx.unique_name("sim2real-nb-"))
    )
    assert code == "InvalidRequestException", code
    assert message == not_spark, repr(message)

    # Effect absent: nothing was created. ListNotebookMetadata itself only operates on
    # Spark-enabled workgroups, so calling it against a plain SQL workgroup is rejected the
    # same way -- consistently demonstrating that no notebook infrastructure exists here.
    list_code, list_message = _error(lambda: athena.list_notebook_metadata(WorkGroup=sql_wg))
    assert list_code == "InvalidRequestException", list_code
    assert list_message == not_spark, repr(list_message)

    # Positive control: the same call against a Spark-enabled workgroup succeeds.
    setup = _setup_spark_workgroup(ctx)
    spark_wg = setup["workgroup"]
    name = ctx.unique_name("sim2real-nb-")
    created = athena.create_notebook(WorkGroup=spark_wg, Name=name)
    notebook_id = created["NotebookId"]

    def _cleanup_notebook() -> None:
        from botocore.exceptions import ClientError

        try:
            athena.delete_notebook(NotebookId=notebook_id)
        except ClientError as exc:
            if "not found" not in exc.response["Error"].get("Message", ""):
                raise

    ctx.on_cleanup(_cleanup_notebook)

    meta = athena.get_notebook_metadata(NotebookId=notebook_id)["NotebookMetadata"]
    assert meta["Name"] == name
    assert meta["WorkGroup"] == spark_wg


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because accepting input AWS refuses must not read as a mere error mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_wg(athena: Any, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    except ClientError as exc:
        # Only an unknown workgroup ("WorkGroup is not found.") means nothing is left.
        if "not found" not in exc.response["Error"].get("Message", ""):
            raise


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 300.0,
    interval_s: float = 10.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_spark_workgroup_when_role_ready(
    athena: Any,
    *,
    workgroup: str,
    role_arn: str,
    bucket_name: str,
    timeout_s: float = 90.0,
    interval_s: float = 10.0,
) -> None:
    """Athena validates the ExecutionRole against IAM at CreateWorkGroup time, so a role
    created moments ago can still be rejected while it propagates. Retry on ClientError
    instead of a blind sleep."""
    from botocore.exceptions import ClientError

    last_err: ClientError | None = None

    def _attempt() -> bool:
        nonlocal last_err
        try:
            athena.create_work_group(
                Name=workgroup,
                Configuration={
                    "ExecutionRole": role_arn,
                    "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
                    "ResultConfiguration": {"OutputLocation": f"s3://{bucket_name}/"},
                },
            )
            return True
        except ClientError as err:
            last_err = err
            return False

    try:
        _poll_until(_attempt, lambda ok: ok, timeout_s=timeout_s, interval_s=interval_s)
    except TimeoutError:
        raise TimeoutError(
            f"create_work_group for {workgroup} did not accept ExecutionRole {role_arn} "
            f"within {timeout_s}s; last error: {last_err}"
        ) from last_err


_SPARK_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
    "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
]


def _setup_spark_workgroup(ctx) -> dict[str, str]:
    from botocore.exceptions import ClientError

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
    # us-east-1 literal: S3's CreateBucket rejects an explicit LocationConstraint for that
    # region specifically -- not a region pin, just the API's one hardcoded special case.
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

    workgroup = ctx.unique_name("sim2real-spark-wg-")
    _create_spark_workgroup_when_role_ready(
        athena,
        workgroup=workgroup,
        role_arn=role_arn,
        bucket_name=bucket_name,
    )

    def _cleanup_wg() -> None:
        try:
            athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
        except ClientError as exc:
            if "not found" not in exc.response["Error"].get("Message", ""):
                raise

    ctx.on_cleanup(_cleanup_wg)

    return {"workgroup": workgroup, "bucket": bucket_name, "role_arn": role_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
