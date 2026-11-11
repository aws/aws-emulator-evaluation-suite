"""deploy-table-bucket-via-cloudformation-behaves."""
from __future__ import annotations

import json
import re

from behavioral_harness import tags

CHECK = "deploy-table-bucket-via-cloudformation-behaves"
GROUP = "deploy"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table bucket + namespace deployed via CloudFormation are not just CREATE_COMPLETE:
    a table can be created inside the deployed namespace via the API and its metadata
    read back correctly through GetTable."""
    bucket_name = ctx.unique_name("sim2real-s3t-cfn-")
    namespace_name = _sanitize(ctx.unique_name("sim2real_ns_"))

    template = {
        "Resources": {
            "TableBucket": {
                "Type": "AWS::S3Tables::TableBucket",
                "Properties": {"TableBucketName": bucket_name},
            },
            "Namespace": {
                "Type": "AWS::S3Tables::Namespace",
                "Properties": {
                    "TableBucketARN": {"Fn::GetAtt": ["TableBucket", "TableBucketARN"]},
                    "Namespace": namespace_name,
                },
            },
        },
        "Outputs": {
            "TableBucketArn": {"Value": {"Fn::GetAtt": ["TableBucket", "TableBucketARN"]}},
        },
    }

    outputs = _deploy_cfn(ctx, json.dumps(template))
    bucket_arn = outputs["TableBucketArn"]

    s3tables = ctx.client("s3tables")
    table_name = _sanitize(ctx.unique_name("sim2real_tbl_"))
    create_resp = s3tables.create_table(
        tableBucketARN=bucket_arn,
        namespace=namespace_name,
        name=table_name,
        format="ICEBERG",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name)
    )

    table = s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name)
    assert table["name"] == table_name, f"expected name {table_name!r}, got {table['name']!r}"
    assert table["namespace"] == [namespace_name], (
        f"expected namespace [{namespace_name!r}], got {table['namespace']!r}"
    )
    assert table["format"] == "ICEBERG", f"expected format ICEBERG, got {table['format']!r}"
    assert table["tableARN"] == create_resp["tableARN"], (
        f"GetTable tableARN {table['tableARN']!r} != CreateTable tableARN {create_resp['tableARN']!r}"
    )
    assert table["tableARN"].startswith(bucket_arn + "/table/"), (
        f"expected tableARN under {bucket_arn}/table/, got {table['tableARN']!r}"
    )


def _sanitize(name: str) -> str:
    """s3tables namespace/table names allow only [0-9a-z_]."""
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


def _deploy_cfn(ctx, template_body: str) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-s3t-stack-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    return {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
