"""notebook-ops-reject-unknown-notebook."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notebook-ops-reject-unknown-notebook"
GROUP = 'overly-permissive'
SERVICES = ['athena']

def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _assert_all_reject(cases, expected):
    """Assert every (label, callable) case fails with exactly *expected*, reporting all at once.

    A call that wrongly succeeds raises immediately.
    """
    actual = {label: _error(fn) for label, fn in cases}
    deviations = {label: got for label, got in actual.items() if got != expected}
    assert not deviations, f"expected {expected} from every call; deviations: {deviations}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Notebook operations that succeed on a real notebook reject an unknown notebook id with
    InvalidRequestException, and notebook create, import and list are refused on a workgroup
    that is not Spark-enabled."""
    athena = ctx.client("athena")

    role_arn = _iam_role_for_spark(ctx)
    spark_wg = _spark_workgroup(ctx, role_arn)

    payload = '{"cells":[],"metadata":{},"nbformat":4,"nbformat_minor":5}'
    name = ctx.unique_name("sim2real-behav-nb-")
    notebook_id = athena.create_notebook(WorkGroup=spark_wg, Name=name)["NotebookId"]
    ctx.on_cleanup(lambda: _safe_delete_notebook(athena, notebook_id))

    # Positive control: each operation tested below succeeds against the real notebook.
    meta = athena.get_notebook_metadata(NotebookId=notebook_id)["NotebookMetadata"]
    assert meta["Name"] == name
    renamed = ctx.unique_name("sim2real-behav-nb-renamed-")
    athena.update_notebook_metadata(NotebookId=notebook_id, Name=renamed)
    meta = athena.get_notebook_metadata(NotebookId=notebook_id)["NotebookMetadata"]
    assert meta["Name"] == renamed
    athena.update_notebook(NotebookId=notebook_id, Payload=payload, Type="IPYNB")
    exported = athena.export_notebook(NotebookId=notebook_id)
    assert json.loads(exported["Payload"])["cells"] == []
    listed = {
        item["NotebookId"]
        for item in athena.list_notebook_metadata(WorkGroup=spark_wg)["NotebookMetadataList"]
    }
    assert notebook_id in listed
    imported_id = athena.import_notebook(
        WorkGroup=spark_wg,
        Name=ctx.unique_name("sim2real-behav-nb-imp-"),
        Payload=payload,
        Type="IPYNB",
    )["NotebookId"]
    ctx.on_cleanup(lambda: _safe_delete_notebook(athena, imported_id))
    assert imported_id != notebook_id

    missing_notebook = "00000000-0000-0000-0000-000000000002"

    _assert_all_reject(
        [
            ("GetNotebookMetadata", lambda: athena.get_notebook_metadata(NotebookId=missing_notebook)),
            (
                "UpdateNotebookMetadata",
                lambda: athena.update_notebook_metadata(
                    NotebookId=missing_notebook, Name=ctx.unique_name("sim2real-behav-nb-")
                ),
            ),
            (
                "UpdateNotebook",
                lambda: athena.update_notebook(
                    NotebookId=missing_notebook, Payload=payload, Type="IPYNB"
                ),
            ),
            ("ExportNotebook", lambda: athena.export_notebook(NotebookId=missing_notebook)),
            ("DeleteNotebook", lambda: athena.delete_notebook(NotebookId=missing_notebook)),
        ],
        ("InvalidRequestException", f"Notebook {missing_notebook} was not found"),
    )

    # A plain SQL workgroup refuses notebook creation, import and listing regardless of id.
    sql_wg = ctx.unique_name("sim2real-behav-sql-wg-")
    athena.create_work_group(Name=sql_wg, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_wg(athena, sql_wg))

    _assert_all_reject(
        [
            ("ListNotebookMetadata", lambda: athena.list_notebook_metadata(WorkGroup=sql_wg)),
            (
                "CreateNotebook",
                lambda: athena.create_notebook(WorkGroup=sql_wg, Name=ctx.unique_name("sim2real-behav-nb-")),
            ),
            (
                "ImportNotebook",
                lambda: athena.import_notebook(
                    WorkGroup=sql_wg,
                    Name=ctx.unique_name("sim2real-behav-nb-imp-"),
                    Payload=payload,
                    Type="IPYNB",
                ),
            ),
        ],
        ("InvalidRequestException", "Workgroup EngineVersion is not Spark."),
    )


def _safe_delete_notebook(athena, notebook_id) -> None:
    try:
        athena.delete_notebook(NotebookId=notebook_id)
    except ClientError as exc:
        if not _not_found(exc):
            raise


def _safe_delete_wg(athena, name) -> None:
    try:
        athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
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


def _iam_role_for_spark(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-athena-spark-role-")
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
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    policies = [
        "arn:aws:iam::aws:policy/AmazonAthenaFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess",
        "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess",
    ]
    for arn in policies:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: _safe_detach_policy(iam, role_name, a))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _safe_delete_role(iam, role_name) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_detach_policy(iam, role_name, policy_arn) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _spark_workgroup(ctx, role_arn):
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-spark-wg-")
    bucket = _s3_output_bucket(ctx)
    config = {
        "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
        "ExecutionRole": role_arn,
        "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/athena-spark-results/"},
    }
    # Freshly attached role policies are not always visible to Athena yet, so retry on the
    # role-propagation error only.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            athena.create_work_group(
                Name=name, Configuration=config, Tags=[{"Key": "sim2real", "Value": CHECK}]
            )
            break
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            if "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    ctx.on_cleanup(lambda: _safe_delete_wg(athena, name))
    return name


def _s3_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-athena-out-")
    kwargs = {}
    if ctx.region != "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint of us-east-1.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
