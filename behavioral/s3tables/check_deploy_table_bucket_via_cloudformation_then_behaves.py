"""deploy-table-bucket-via-cloudformation-then-behaves."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deploy-table-bucket-via-cloudformation-then-behaves"
GROUP = "deploy"
SERVICES = ["s3tables"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  BucketName:
    Type: String
Resources:
  TableBucket:
    Type: AWS::S3Tables::TableBucket
    Properties:
      TableBucketName: !Ref BucketName
Outputs:
  TableBucketArn:
    Value: !GetAtt TableBucket.TableBucketARN
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table bucket provisioned via CloudFormation is a live, functional resource:
    it can immediately host a namespace + table created through the plain API, and
    GetTableBucket / ListTables read the CFN-managed bucket back correctly."""
    cfn = ctx.client("cloudformation")
    s3tables = ctx.client("s3tables")

    stack_name = ctx.unique_name("sim2real-s3t-cfnbucket-")
    bucket_name = ctx.unique_name("sim2real-s3t-bkt-")

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "BucketName", "ParameterValue": bucket_name}],
    )
    ctx.on_cleanup(_delete_stack)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    bucket_arn = outputs["TableBucketArn"]
    s3tables.tag_resource(resourceArn=bucket_arn, tags={"sim2real": "s3tables-cfn-audit"})

    # The stack-managed bucket must be immediately addressable via the plain API.
    got_bucket = s3tables.get_table_bucket(tableBucketARN=bucket_arn)
    assert got_bucket["arn"] == bucket_arn, f"expected arn {bucket_arn}, got {got_bucket['arn']}"
    assert got_bucket["name"] == bucket_name, (
        f"expected name {bucket_name}, got {got_bucket['name']}"
    )

    ns_name = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[ns_name])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=ns_name))

    table_name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    created = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=ns_name, name=table_name, format="ICEBERG"
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    )
    assert created["tableARN"].startswith(bucket_arn + "/table/"), (
        f"expected tableARN under {bucket_arn}/table/, got {created['tableARN']}"
    )
    assert created["versionToken"], "CreateTable returned no versionToken"

    listed = s3tables.list_tables(tableBucketARN=bucket_arn, namespace=ns_name)["tables"]
    names = [t["name"] for t in listed]
    assert table_name in names, f"table {table_name} not visible via ListTables: {names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
