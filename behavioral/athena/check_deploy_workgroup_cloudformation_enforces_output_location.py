"""deploy-workgroup-cloudformation-enforces-output-location."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-workgroup-cloudformation-enforces-output-location"
GROUP = "deploy"
SERVICES = ["athena"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  WorkGroupName:
    Type: String
  BucketName:
    Type: String
  OutputPrefix:
    Type: String
Resources:
  QueryWorkGroup:
    Type: AWS::Athena::WorkGroup
    Properties:
      Name: !Ref WorkGroupName
      State: ENABLED
      RecursiveDeleteOption: true
      WorkGroupConfiguration:
        EnforceWorkGroupConfiguration: true
        PublishCloudWatchMetricsEnabled: false
        ResultConfiguration:
          OutputLocation: !Sub "s3://${BucketName}/${OutputPrefix}/"
Outputs:
  WorkGroupName:
    Value: !Ref QueryWorkGroup
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation workgroup with EnforceWorkGroupConfiguration runs a query with no explicit
    output location into the stack-defined S3 location; deleting the stack removes the workgroup
    (GetWorkGroup then fails)."""
    bucket = _create_bucket(ctx)
    wg_name = ctx.unique_name("sim2real-behav-wg-")
    prefix = "athena-results"
    stack_name, outputs = _deploy_stack(
        ctx,
        _TEMPLATE,
        [
            {"ParameterKey": "WorkGroupName", "ParameterValue": wg_name},
            {"ParameterKey": "BucketName", "ParameterValue": bucket},
            {"ParameterKey": "OutputPrefix", "ParameterValue": prefix},
        ],
    )
    assert outputs["WorkGroupName"] == wg_name, (
        f"expected stack output WorkGroupName={wg_name!r}, got {outputs.get('WorkGroupName')!r}"
    )

    athena = ctx.client("athena")
    wg = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]
    assert wg["Configuration"]["EnforceWorkGroupConfiguration"] is True, (
        f"expected EnforceWorkGroupConfiguration=True, got "
        f"{wg['Configuration'].get('EnforceWorkGroupConfiguration')!r}"
    )
    expected_location = f"s3://{bucket}/{prefix}/"
    actual_wg_location = wg["Configuration"]["ResultConfiguration"]["OutputLocation"]
    assert actual_wg_location == expected_location, (
        f"expected workgroup OutputLocation={expected_location!r}, got {actual_wg_location!r}"
    )

    qid = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name)["QueryExecutionId"]
    state, execution = _wait_query_terminal(ctx, qid, timeout_s=120)
    assert state == "SUCCEEDED", f"query did not succeed: {execution['Status']}"
    actual_location = execution["ResultConfiguration"]["OutputLocation"]
    assert actual_location.startswith(expected_location), (
        f"expected output under stack-defined location {expected_location!r}, got {actual_location!r}"
    )

    _delete_stack_and_wait(ctx, stack_name)
    code, message = _error(lambda: athena.get_work_group(WorkGroup=wg_name))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException reading the workgroup after its owning "
        f"stack was deleted, got {code!r}"
    )
    assert message == "WorkGroup is not found.", f"expected 'WorkGroup is not found.', got {message!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-athena-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _deploy_stack(ctx, template_body: str, parameters: list) -> tuple[str, dict]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    # Safety net: the check deletes the stack itself, since a stack delete can outlast cleanup;
    # delete_stack on an already-deleted stack is a no-op.
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return stack_name, outputs


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _wait_query_terminal(ctx, query_execution_id: str, timeout_s: float = 120.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    execution = None
    while time.monotonic() < deadline:
        execution = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"]
        state = execution["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state, execution
        time.sleep(2)
    raise AssertionError(f"query {query_execution_id} did not reach a terminal state in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
