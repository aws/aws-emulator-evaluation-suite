"""notebook-lifecycle-create-update-export-import-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notebook-lifecycle-create-update-export-import-delete"
GROUP = "state-machine"
SERVICES = ["athena"]

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNotebook yields an empty ipynb, metadata/content updates show in Get/Export, an
    export->import round trips the exact bytes, and DeleteNotebook drops it from the listing."""
    athena = ctx.client("athena")
    role_arn = _iam_role_for_spark(ctx)
    workgroup = _spark_workgroup(ctx, role_arn)

    original_name = ctx.unique_name("sim2real-nb-")
    notebook_id = athena.create_notebook(WorkGroup=workgroup, Name=original_name)["NotebookId"]
    ctx.on_cleanup(lambda: _safe_delete_notebook(ctx, notebook_id))

    meta = athena.get_notebook_metadata(NotebookId=notebook_id)["NotebookMetadata"]
    assert meta["Name"] == original_name, f"expected Name={original_name!r}, got {meta['Name']!r}"
    assert meta["WorkGroup"] == workgroup, f"expected WorkGroup={workgroup!r}, got {meta['WorkGroup']!r}"
    assert meta["Type"] == "IPYNB", f"expected Type='IPYNB', got {meta['Type']!r}"

    renamed = ctx.unique_name("sim2real-nb-renamed-")
    athena.update_notebook_metadata(NotebookId=notebook_id, Name=renamed)
    meta = athena.get_notebook_metadata(NotebookId=notebook_id)["NotebookMetadata"]
    assert meta["Name"] == renamed, f"expected Name={renamed!r} after UpdateNotebookMetadata, got {meta['Name']!r}"

    exported = athena.export_notebook(NotebookId=notebook_id)
    assert exported["NotebookMetadata"]["Name"] == renamed, (
        f"expected exported Name={renamed!r}, got {exported['NotebookMetadata']['Name']!r}"
    )
    exported_payload = json.loads(exported["Payload"])
    assert exported_payload["cells"] == [], f"expected a fresh notebook to have no cells, got {exported_payload['cells']!r}"

    marker_cell = {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": ["# sim2real-marker\n"],
    }
    updated_payload = json.dumps(
        {"cells": [marker_cell], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    )
    athena.update_notebook(NotebookId=notebook_id, Payload=updated_payload, Type="IPYNB")

    re_exported = json.loads(athena.export_notebook(NotebookId=notebook_id)["Payload"])
    assert len(re_exported["cells"]) == 1, f"expected 1 cell after UpdateNotebook, got {len(re_exported['cells'])}"
    assert re_exported["cells"][0]["source"] == ["# sim2real-marker\n"], (
        f"expected the marker cell source, got {re_exported['cells'][0]['source']!r}"
    )

    imported_name = ctx.unique_name("sim2real-nb-imported-")
    imported_id = athena.import_notebook(
        WorkGroup=workgroup, Name=imported_name, Type="IPYNB", Payload=updated_payload
    )["NotebookId"]
    ctx.on_cleanup(lambda: _safe_delete_notebook(ctx, imported_id))
    assert imported_id != notebook_id, "ImportNotebook returned the same NotebookId as the original"

    round_tripped = json.loads(athena.export_notebook(NotebookId=imported_id)["Payload"])
    assert round_tripped["cells"] == [marker_cell], "ImportNotebook payload did not round-trip byte-identically"

    athena.delete_notebook(NotebookId=notebook_id)
    athena.delete_notebook(NotebookId=imported_id)

    remaining_ids = {
        item["NotebookId"]
        for item in athena.list_notebook_metadata(WorkGroup=workgroup)["NotebookMetadataList"]
    }
    assert notebook_id not in remaining_ids, f"deleted notebook {notebook_id} still in ListNotebookMetadata"
    assert imported_id not in remaining_ids, f"deleted notebook {imported_id} still in ListNotebookMetadata"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    config = {
        "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
        "ExecutionRole": role_arn,
        "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/athena-spark-results/"},
    }
    # A fresh IAM role takes seconds to propagate before Athena accepts it as ExecutionRole.
    deadline = time.monotonic() + 30.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            athena.create_work_group(
                Name=name,
                Configuration=config,
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
            return name
        except athena.exceptions.InvalidRequestException as exc:
            last_error = exc
            time.sleep(2.0)
    raise AssertionError(f"could not create Spark-enabled workgroup: {last_error}")


def _s3_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-out-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
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


def _safe_delete_notebook(ctx, notebook_id):
    athena = ctx.client("athena")
    try:
        athena.delete_notebook(NotebookId=notebook_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err.get("Code") == "InvalidRequestException" and "was not found" in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
