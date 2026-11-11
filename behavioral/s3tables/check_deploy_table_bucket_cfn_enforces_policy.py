"""deploy-table-bucket-cfn-enforces-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-table-bucket-cfn-enforces-policy"
GROUP = "state-machine"
SERVICES = ["s3tables"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
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


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-provisioned table bucket hosts namespaces and tables like an API-created one, and
    an explicit Deny in its resource policy is enforced (AccessDeniedException) until the policy is removed.
    """
    cfn = ctx.client("cloudformation")
    s3tables = ctx.client("s3tables")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    bucket_name = ctx.unique_name("sim2real-cfn-bucket-")
    stack_name = ctx.unique_name("sim2real-cfn-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "BucketName", "ParameterValue": bucket_name}],
    )
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    bucket_arn = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "TableBucketArn")

    namespace = _safe_name(ctx, "sim2real-cfn-ns-")
    table_name = _safe_name(ctx, "sim2real-cfn-tbl-")

    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: _delete_namespace_quiet(s3tables, bucket_arn, namespace))
    table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=table_name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(lambda: _delete_table_quiet(s3tables, bucket_arn, namespace, table_name))

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyDeleteTable",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3tables:DeleteTable",
                "Resource": table_arn,
            }
        ],
    }
    s3tables.put_table_bucket_policy(tableBucketARN=bucket_arn, resourcePolicy=json.dumps(deny_policy))

    stored = json.loads(s3tables.get_table_bucket_policy(tableBucketARN=bucket_arn)["resourcePolicy"])
    assert stored == deny_policy, f"policy did not round-trip: {stored}"

    # Negative: the explicit Deny must block DeleteTable. The authorization layer
    # rejects with AccessDeniedException, not the service's own ForbiddenException.
    code, message = _error(
        lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == (
        f"User: {caller_arn} is not authorized to perform: s3tables:DeleteTable on resource: "
        f"{table_arn} with an explicit deny in a resource-based policy"
    ), message

    # Effect absent: the table is still there.
    described = s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    assert described["name"] == table_name, f"expected table {table_name} intact, got {described}"

    # Positive control: remove the policy, the same delete now succeeds.
    s3tables.delete_table_bucket_policy(tableBucketARN=bucket_arn)
    s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)

    code, message = _error(
        lambda: s3tables.get_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    )
    assert code == "NotFoundException", f"expected table gone, got {code}"
    assert message == "The specified table does not exist.", message

    # Deploy teardown must be proven, not fired-and-forgotten: delete the namespace
    # (now empty) and the stack, then read the CFN-managed bucket independently.
    s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
    cfn.delete_stack(StackName=stack_name)
    _wait_stack(cfn, stack_name, "stack_delete_complete")

    code, message = _error(lambda: s3tables.get_table_bucket(tableBucketARN=bucket_arn))
    assert code == "NotFoundException", f"expected table bucket gone after stack delete, got {code}"
    assert message == "The specified bucket does not exist.", message


def _safe_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_stack(cfn, stack_name: str, waiter_name: str) -> None:
    waiter = cfn.get_waiter(waiter_name)
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    except WaiterError as err:
        raise AssertionError(f"stack {stack_name} did not reach expected state: {err}") from err


def _delete_namespace_quiet(s3tables, bucket_arn: str, namespace: str) -> None:
    try:
        s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
    except s3tables.exceptions.NotFoundException:
        pass


def _delete_table_quiet(s3tables, bucket_arn: str, namespace: str, name: str) -> None:
    try:
        s3tables.delete_table_bucket_policy(tableBucketARN=bucket_arn)
    except s3tables.exceptions.NotFoundException:
        pass
    try:
        s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    except s3tables.exceptions.NotFoundException:
        pass


def _delete_stack_quiet(cfn, stack_name: str) -> None:
    # DeleteStack on a deleted stack is a no-op and the waiter treats a missing stack as deleted.
    cfn.delete_stack(StackName=stack_name)
    _wait_stack(cfn, stack_name, "stack_delete_complete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
