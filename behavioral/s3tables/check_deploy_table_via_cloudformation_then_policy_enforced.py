"""deploy-table-via-cloudformation-then-policy-enforced."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-table-via-cloudformation-then-policy-enforced"
GROUP = "server-side"
SERVICES = ["s3tables"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  BucketName:
    Type: String
  NamespaceName:
    Type: String
  TableName:
    Type: String
Resources:
  TableBucket:
    Type: AWS::S3Tables::TableBucket
    Properties:
      TableBucketName: !Ref BucketName
  Namespace:
    Type: AWS::S3Tables::Namespace
    Properties:
      TableBucketARN: !GetAtt TableBucket.TableBucketARN
      Namespace: !Ref NamespaceName
  Table:
    Type: AWS::S3Tables::Table
    DependsOn: Namespace
    Properties:
      TableBucketARN: !GetAtt TableBucket.TableBucketARN
      Namespace: !Ref NamespaceName
      TableName: !Ref TableName
      OpenTableFormat: ICEBERG
      WithoutMetadata: "Yes"
Outputs:
  TableBucketArn:
    Value: !GetAtt TableBucket.TableBucketARN
  TableArn:
    Value: !GetAtt Table.TableARN
"""


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be denied, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A table created by a CloudFormation stack accepts PutTablePolicy and returns the policy from
    GetTablePolicy; an explicit Deny on GetTable refuses the read with AccessDeniedException while the
    table stays listed, and restoring the Allow policy makes the same read succeed."""
    cfn = ctx.client("cloudformation")
    s3tables = ctx.client("s3tables")
    caller = ctx.client("sts").get_caller_identity()
    account_id = caller["Account"]

    stack_name = ctx.unique_name("sim2real-s3t-cfntable-")
    bucket_name = ctx.unique_name("sim2real-s3t-bkt-")
    ns_name = ctx.unique_name("sim2real_ns_").replace("-", "_")
    table_name = ctx.unique_name("sim2real_tbl_").replace("-", "_")

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "BucketName", "ParameterValue": bucket_name},
            {"ParameterKey": "NamespaceName", "ParameterValue": ns_name},
            {"ParameterKey": "TableName", "ParameterValue": table_name},
        ],
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
    table_arn = outputs["TableArn"]

    # Positive control: the CFN-deployed table is reachable before any resource policy exists.
    baseline = s3tables.get_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    assert baseline["name"] == table_name, baseline

    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "s3tables:GetTable",
                "Resource": table_arn,
            }
        ],
    }
    s3tables.put_table_policy(
        tableBucketARN=bucket_arn,
        namespace=ns_name,
        name=table_name,
        resourcePolicy=json.dumps(allow_policy),
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table_policy(
            tableBucketARN=bucket_arn, namespace=ns_name, name=table_name
        )
    )

    got = s3tables.get_table_policy(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    got_policy = json.loads(got["resourcePolicy"])
    assert got_policy["Statement"][0]["Action"] == "s3tables:GetTable", got_policy
    assert got_policy["Statement"][0]["Resource"] == table_arn, got_policy

    # Break exactly one thing: replace the policy with an explicit Deny on the same action.
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SimParityDenyGetTable",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3tables:GetTable",
                "Resource": table_arn,
            }
        ],
    }
    s3tables.put_table_policy(
        tableBucketARN=bucket_arn,
        namespace=ns_name,
        name=table_name,
        resourcePolicy=json.dumps(deny_policy),
    )

    error = _client_error(
        lambda: s3tables.get_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    )
    assert error.get("Code") == "AccessDeniedException", f"expected AccessDeniedException, got {error}"
    assert error.get("Message") == (
        f"User: {caller['Arn']} is not authorized to perform: s3tables:GetTable on resource: "
        f"{table_arn} with an explicit deny in a resource-based policy"
    ), error

    # Effect absent: the table itself is untouched, visible via an independent list read.
    names = [
        t["name"]
        for t in s3tables.list_tables(tableBucketARN=bucket_arn, namespace=ns_name)["tables"]
    ]
    assert table_name in names, names

    # Restore the prior Allow policy: the identical read succeeds again.
    s3tables.put_table_policy(
        tableBucketARN=bucket_arn,
        namespace=ns_name,
        name=table_name,
        resourcePolicy=json.dumps(allow_policy),
    )
    restored = s3tables.get_table(tableBucketARN=bucket_arn, namespace=ns_name, name=table_name)
    assert restored["name"] == table_name, restored


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
