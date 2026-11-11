"""deploy-table-bucket-then-create-namespace-and-table."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-table-bucket-then-create-namespace-and-table"
GROUP = "deploy"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table bucket deployed via CloudFormation is actually usable afterwards:
    CreateNamespace and CreateTable succeed against it and GetTableBucket resolves it.
    The created table is then deleted and proven gone via an independent read."""
    bucket_name = ctx.unique_name("sim2real-s3t-deploy-")
    stack_name = ctx.unique_name("sim2real-s3t-stack-")
    template = json.dumps(
        {
            "Resources": {
                "TableBucket": {
                    "Type": "AWS::S3Tables::TableBucket",
                    "Properties": {"TableBucketName": bucket_name},
                }
            },
            "Outputs": {
                "TableBucketArn": {"Value": {"Fn::GetAtt": ["TableBucket", "TableBucketARN"]}}
            },
        }
    )
    arn = _deploy_cfn(ctx, stack_name, template)

    s3tables = ctx.client("s3tables")
    bucket = s3tables.get_table_bucket(tableBucketARN=arn)
    assert bucket["arn"] == arn, f"expected bucket arn {arn}, got {bucket['arn']}"
    assert bucket["name"] == bucket_name, (
        f"expected bucket name {bucket_name}, got {bucket['name']}"
    )

    namespace_name = ctx.unique_name("ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=arn, namespace=[namespace_name])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=arn, namespace=namespace_name))

    table_name = ctx.unique_name("tbl_").replace("-", "_")
    created = s3tables.create_table(
        tableBucketARN=arn, namespace=namespace_name, name=table_name, format="ICEBERG"
    )
    ctx.on_cleanup(lambda: _delete_table_quiet(s3tables, arn, namespace_name, table_name))
    assert created["tableARN"].startswith(arn + "/table/"), (
        f"expected tableARN under {arn}/table/, got {created['tableARN']}"
    )
    assert created.get("versionToken"), (
        f"expected a non-empty versionToken, got {created.get('versionToken')!r}"
    )

    got = s3tables.get_table(tableBucketARN=arn, namespace=namespace_name, name=table_name)
    assert got["name"] == table_name, f"expected table name {table_name}, got {got['name']}"
    assert got["format"] == "ICEBERG", f"expected format ICEBERG, got {got['format']}"

    # Deleting the table must make it unreadable: prove it with an independent read.
    s3tables.delete_table(tableBucketARN=arn, namespace=namespace_name, name=table_name)
    code, message = _error(
        lambda: s3tables.get_table(tableBucketARN=arn, namespace=namespace_name, name=table_name)
    )
    assert code == "NotFoundException", f"expected table gone after delete, got {code}"
    assert message == "The specified table does not exist.", (
        f"expected the exact not-found message for the deleted table, got {message!r}"
    )


def _deploy_cfn(ctx: Any, stack_name: str, template_body: str) -> str:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    arn_by_key = {o["OutputKey"]: o["OutputValue"] for o in outputs}
    return arn_by_key["TableBucketArn"]


def _delete_stack(ctx: Any, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _delete_table_quiet(s3tables: Any, arn: str, namespace: str, name: str) -> None:
    try:
        s3tables.delete_table(tableBucketARN=arn, namespace=namespace, name=name)
    except s3tables.exceptions.NotFoundException:
        pass


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
