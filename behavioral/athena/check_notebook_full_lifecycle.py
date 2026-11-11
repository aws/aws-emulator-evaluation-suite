"""notebook-full-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "notebook-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Created notebook metadata is visible via Get/List, updates land and export byte-identical,
    ImportNotebook creates a distinct notebook, a bound session gets a presigned URL, and
    DeleteNotebook removes the notebook."""
    athena = ctx.client("athena")
    setup = _setup_spark_workgroup(ctx)
    workgroup = setup["workgroup"]

    name = ctx.unique_name("sim2real-nb-")
    created = athena.create_notebook(WorkGroup=workgroup, Name=name)
    notebook_id = created["NotebookId"]
    notebook_deleted = {"value": False}

    def _cleanup_notebook() -> None:
        if not notebook_deleted["value"]:
            from botocore.exceptions import ClientError

            try:
                athena.delete_notebook(NotebookId=notebook_id)
            except ClientError as exc:
                if not _not_found(exc):
                    raise

    ctx.on_cleanup(_cleanup_notebook)

    meta = athena.get_notebook_metadata(NotebookId=notebook_id)["NotebookMetadata"]
    assert meta["Name"] == name, f"expected Name={name!r}, got {meta['Name']!r}"
    assert meta["WorkGroup"] == workgroup, f"expected WorkGroup={workgroup!r}, got {meta['WorkGroup']!r}"
    assert meta["Type"] == "IPYNB", f"expected Type=IPYNB, got {meta['Type']!r}"

    listed = athena.list_notebook_metadata(WorkGroup=workgroup)["NotebookMetadataList"]
    listed_ids = {n["NotebookId"] for n in listed}
    assert notebook_id in listed_ids, f"expected {notebook_id!r} in ListNotebookMetadata, got {listed_ids!r}"

    payload_v1 = json.dumps(
        {
            "cells": [{"cell_type": "code", "source": "print('v1')", "metadata": {}, "outputs": []}],
            "metadata": {},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
    )
    athena.update_notebook(NotebookId=notebook_id, Payload=payload_v1, Type="IPYNB")

    renamed = ctx.unique_name("sim2real-nb-renamed-")
    athena.update_notebook_metadata(NotebookId=notebook_id, Name=renamed)
    meta_after_rename = athena.get_notebook_metadata(NotebookId=notebook_id)["NotebookMetadata"]
    assert meta_after_rename["Name"] == renamed, (
        f"expected Name={renamed!r} after UpdateNotebookMetadata, got {meta_after_rename['Name']!r}"
    )

    exported = athena.export_notebook(NotebookId=notebook_id)
    exported_name = exported["NotebookMetadata"]["Name"]
    assert exported_name == renamed, f"expected exported Name={renamed!r}, got {exported_name!r}"
    exported_payload = exported["Payload"]
    exported_json = json.loads(exported_payload)
    expected_json = json.loads(payload_v1)
    assert exported_json == expected_json, f"expected ExportNotebook payload={expected_json!r}, got {exported_json!r}"

    imported_name = ctx.unique_name("sim2real-nb-imported-")
    imported = athena.import_notebook(
        WorkGroup=workgroup, Name=imported_name, Type="IPYNB", Payload=exported_payload
    )
    imported_id = imported["NotebookId"]
    assert imported_id != notebook_id, "ImportNotebook must create a distinct notebook, not reuse the source id"

    def _cleanup_imported() -> None:
        from botocore.exceptions import ClientError

        try:
            athena.delete_notebook(NotebookId=imported_id)
        except ClientError as exc:
            if not _not_found(exc):
                raise

    ctx.on_cleanup(_cleanup_imported)

    imported_meta = athena.get_notebook_metadata(NotebookId=imported_id)["NotebookMetadata"]
    assert imported_meta["Name"] == imported_name, (
        f"expected imported Name={imported_name!r}, got {imported_meta['Name']!r}"
    )
    assert imported_meta["WorkGroup"] == workgroup, (
        f"expected imported WorkGroup={workgroup!r}, got {imported_meta['WorkGroup']!r}"
    )

    session_id = _start_session(
        ctx,
        workgroup,
        extra_engine_config={"AdditionalConfigs": {"NotebookId": notebook_id}},
        NotebookVersion="Athena notebook version 1",
    )
    presigned = athena.create_presigned_notebook_url(SessionId=session_id)
    assert presigned["NotebookUrl"].startswith("https://"), (
        f"expected an https NotebookUrl, got {presigned['NotebookUrl']!r}"
    )
    assert presigned["AuthToken"], "expected a non-empty AuthToken from CreatePresignedNotebookUrl"

    # A notebook bound to an active session cannot be deleted; terminate the session first.
    athena.terminate_session(SessionId=session_id)
    _poll_until(
        lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
        lambda st: st in ("TERMINATED", "FAILED"),
        timeout_s=120.0,
        interval_s=5.0,
    )

    athena.delete_notebook(NotebookId=notebook_id)
    notebook_deleted["value"] = True
    gone = ("InvalidRequestException", f"Notebook {notebook_id} was not found")
    deleted = _error(lambda: athena.get_notebook_metadata(NotebookId=notebook_id))
    assert deleted == gone, f"expected {gone}, got {deleted!r}"

    rename_after_delete = _error(
        lambda: athena.update_notebook_metadata(NotebookId=notebook_id, Name=ctx.unique_name("sim2real-nb-dead-"))
    )
    assert rename_after_delete == gone, (
        f"mutation on a deleted notebook should fail with {gone}, got {rename_after_delete!r}"
    )


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


def _error(fn: Callable[[], Any]) -> tuple[str | None, str | None]:
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _not_found(exc: ClientError) -> bool:
    """Athena reports a missing resource as ResourceNotFoundException or an InvalidRequestException saying so."""
    err = exc.response["Error"]
    msg = err.get("Message", "")
    return err.get("Code") == "ResourceNotFoundException" or (
        err.get("Code") == "InvalidRequestException" and ("not found" in msg or "does not exist" in msg)
    )


def _retry_role_propagation(ctx, what: str, call: Callable[[], Any], timeout_s: float) -> Any:
    """Retry call() while Athena cannot yet use the just-created execution role (IAM propagation)."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))
    while True:
        try:
            return call()
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "").lower()
            if not any(k in msg for k in ("misconfigured service role", "assume", "not authorized", "access denied")):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what} never succeeded (role propagation?): {exc}") from exc
        time.sleep(2)


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "notebook-full-lifecycle"}],
    )
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
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "notebook-full-lifecycle"}]},
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
    _retry_role_propagation(
        ctx,
        "CreateWorkGroup",
        lambda: athena.create_work_group(
            Name=workgroup,
            Configuration={
                "ExecutionRole": role_arn,
                "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
                "ResultConfiguration": {"OutputLocation": f"s3://{bucket_name}/"},
            },
            Tags=[{"Key": "sim2real", "Value": "notebook-full-lifecycle"}],
        ),
        timeout_s=90.0,
    )

    def _cleanup_wg() -> None:
        try:
            athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
        except ClientError as exc:
            if not _not_found(exc):
                raise

    ctx.on_cleanup(_cleanup_wg)

    return {"workgroup": workgroup, "bucket": bucket_name, "role_arn": role_arn}


def _start_session(ctx, workgroup: str, extra_engine_config: dict[str, Any] | None = None, **kwargs) -> str:
    from botocore.exceptions import ClientError

    athena = ctx.client("athena")
    engine_configuration = {
        "CoordinatorDpuSize": 1,
        "MaxConcurrentDpus": 3,
        "DefaultExecutorDpuSize": 1,
    }
    if extra_engine_config:
        engine_configuration.update(extra_engine_config)

    session_id = _retry_role_propagation(
        ctx,
        "StartSession",
        lambda: athena.start_session(
            WorkGroup=workgroup, EngineConfiguration=engine_configuration, **kwargs
        )["SessionId"],
        timeout_s=60.0,
    )

    def _cleanup_session() -> None:
        try:
            st = athena.get_session_status(SessionId=session_id)["Status"]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if st not in ("TERMINATED", "TERMINATING", "FAILED"):
            try:
                athena.terminate_session(SessionId=session_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        # A notebook bound to a session that is still terminating cannot be deleted.
        _poll_until(
            lambda: athena.get_session_status(SessionId=session_id)["Status"]["State"],
            lambda s: s in ("TERMINATED", "FAILED"),
            timeout_s=60.0,
            interval_s=2.0,
        )

    ctx.on_cleanup(_cleanup_session)

    try:
        _poll_until(
            lambda: athena.get_session_status(SessionId=session_id)["Status"],
            lambda st: st["State"] in ("IDLE", "FAILED", "DEGRADED"),
            timeout_s=420.0,
            interval_s=10.0,
        )
    except TimeoutError:
        raise AssertionError("session did not leave CREATING within timeout")

    final_state = athena.get_session_status(SessionId=session_id)["Status"]["State"]
    if final_state != "IDLE":
        raise AssertionError(f"session reached {final_state} instead of IDLE (environment issue)")

    return session_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
