"""notebook-import-export-binary-content-byte-identical."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "notebook-import-export-binary-content-byte-identical"
GROUP = "representation"
SERVICES = ["athena"]


def _create_results_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-athena-spark-")
    if ctx.region == "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint on CreateBucket.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
            )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_spark_execution_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "athena.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*", f"arn:aws:s3:::{bucket}"],
            }
        ],
    }
    policy_name = "spark-results-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_spark_workgroup(ctx, role_arn: str, bucket: str) -> str:
    athena = ctx.client("athena")
    workgroup = ctx.unique_name("sim2real-spark-wg-")
    config = {
        "ResultConfiguration": {"OutputLocation": f"s3://{bucket}/spark-results/"},
        "ExecutionRole": role_arn,
        "EngineVersion": {"SelectedEngineVersion": "PySpark engine version 3"},
    }
    wg_tags = [{"Key": "sim2real", "Value": CHECK}]
    # A freshly created IAM role can take a few seconds to propagate before Athena will
    # accept it as a workgroup ExecutionRole; poll the observable condition (create succeeds)
    # rather than sleeping a fixed duration.
    deadline = time.monotonic() + 30.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            athena.create_work_group(Name=workgroup, Configuration=config, Tags=wg_tags)
            ctx.on_cleanup(
                lambda: athena.delete_work_group(WorkGroup=workgroup, RecursiveDeleteOption=True)
            )
            return workgroup
        except athena.exceptions.InvalidRequestException as exc:
            last_error = exc
            time.sleep(2.0)
    raise AssertionError(f"could not create Spark-enabled workgroup: {last_error}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportNotebook with base64 binary content, then ExportNotebook, is byte-identical."""
    athena = ctx.client("athena")
    bucket = _create_results_bucket(ctx)
    role_arn = _create_spark_execution_role(ctx, bucket)
    workgroup = _create_spark_workgroup(ctx, role_arn, bucket)

    binary_blob = bytes(range(256)) * 37  # deterministic pseudo-binary payload
    embedded_b64 = base64.b64encode(binary_blob).decode("ascii")
    notebook_payload = {
        "cells": [
            {
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "source": ["# sim2real byte-identical round trip check\n"],
                "outputs": [
                    {
                        "output_type": "display_data",
                        "data": {"image/png": embedded_b64},
                        "metadata": {},
                    }
                ],
            }
        ],
        "metadata": {"kernelspec": {"name": "python3", "display_name": "Python 3"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    payload_str = json.dumps(notebook_payload)

    notebook_name = ctx.unique_name("sim2real-nb-")
    import_resp = athena.import_notebook(
        WorkGroup=workgroup, Name=notebook_name, Payload=payload_str, Type="IPYNB"
    )
    notebook_id = import_resp["NotebookId"]
    ctx.on_cleanup(lambda: athena.delete_notebook(NotebookId=notebook_id))

    export_resp = athena.export_notebook(NotebookId=notebook_id)
    exported_payload = export_resp["Payload"]

    assert exported_payload == payload_str, "exported notebook payload is not byte-identical to import"
    exported_json = json.loads(exported_payload)
    assert exported_json["cells"][0]["outputs"][0]["data"]["image/png"] == embedded_b64, (
        "embedded base64 binary content was altered by the import/export round trip"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
