"""sam-serverless-application-s3-location-creates-real-nested-stack."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-serverless-application-s3-location-creates-real-nested-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "sqs"]

_CHANGE_SET_NAME = "sim2real-cs1"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Serverless::Application whose Location names an S3 object directly (no packaging, no
    SAM CLI) expands into a real nested stack, and the child's own queue exists in SQS.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-application.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")

    bucket = ctx.unique_name("sim2real-sam-app-")
    queue_name = ctx.unique_name("sim2real-sam-app-")
    stack_name = ctx.unique_name("sim2real-sam-app-")
    key = "children/queue.template"

    _make_bucket(ctx, s3, bucket)

    child_template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::Serverless-2016-10-31",
        "Parameters": {"QueueName": {"Type": "String"}},
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueName"}},
            }
        },
        "Outputs": {"QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}}},
    })
    s3.put_object(Bucket=bucket, Key=key, Body=child_template.encode())

    parent_template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "App": {
                "Type": "AWS::Serverless::Application",
                "Properties": {
                    "Location": f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}",
                    "Parameters": {"QueueName": queue_name},
                },
            }
        },
        "Outputs": {"QueueArn": {"Value": {"Fn::GetAtt": ["App", "Outputs.QueueArn"]}}},
    })

    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    _create_change_set(ctx, stack_name, parent_template, ["CAPABILITY_AUTO_EXPAND"])
    _execute_change_set(cfn, stack_name, _CHANGE_SET_NAME)

    parent = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert parent["StackStatus"] == "CREATE_COMPLETE", (
        f"the parent stack is {parent['StackStatus']!r}"
    )

    resources = cfn.describe_stack_resources(StackName=parent["StackId"])["StackResources"]
    rows = [(r["LogicalResourceId"], r["ResourceType"], r["ResourceStatus"]) for r in resources]
    assert rows == [("App", "AWS::CloudFormation::Stack", "CREATE_COMPLETE")], (
        f"the application must expand into exactly one nested stack; got {rows!r}"
    )
    nested_id = resources[0]["PhysicalResourceId"]

    child = cfn.describe_stacks(StackName=nested_id)["Stacks"][0]
    assert (child["StackStatus"], child["ParentId"], child["RootId"]) == (
        "CREATE_COMPLETE", parent["StackId"], parent["StackId"]
    ), (
        "the nested stack must be CREATE_COMPLETE with the parent as both parent and root; got "
        f"{(child['StackStatus'], child.get('ParentId'), child.get('RootId'))!r}"
    )

    # The S3 object we wrote is what CloudFormation actually ran: nothing repackaged it.
    original = cfn.get_template(StackName=nested_id, TemplateStage="Original")["TemplateBody"]
    original_text = original if isinstance(original, str) else json.dumps(original)
    assert json.loads(original_text) == json.loads(child_template), (
        "the nested stack's template must be exactly the S3 object the Location named"
    )

    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    outputs = {o["OutputKey"]: o["OutputValue"] for o in parent.get("Outputs", [])}
    assert outputs.get("QueueArn") == queue_arn, (
        "the parent's QueueArn output must be the queue SQS itself created; got "
        f"{outputs.get('QueueArn')!r}, SQS reports {queue_arn!r}"
    )


def _make_bucket(ctx, s3, name: str) -> None:
    """Create the bucket with a teardown that empties and deletes it."""
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def empty_and_delete() -> None:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(empty_and_delete)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _create_change_set(ctx, stack_name: str, template_body: str, capabilities: list,
                        *, timeout_s: float = 300.0) -> dict:
    """Create a CREATE change set and poll it to a terminal status."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName=_CHANGE_SET_NAME,
        ChangeSetType="CREATE",
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        Capabilities=capabilities,
    )
    described = _poll_until(
        lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName=_CHANGE_SET_NAME),
        lambda d: d["Status"] in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"change set for {stack_name}",
    )
    assert described["Status"] == "CREATE_COMPLETE", (
        f"change set ended {described['Status']!r}: {described.get('StatusReason')!r}"
    )
    return described


def _execute_change_set(cfn, stack_name: str, change_set_name: str,
                         *, timeout_s: float = 900.0) -> None:
    """Execute a change set and wait for the stack to reach a terminal status."""
    cfn.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith(("_COMPLETE", "_FAILED")),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name}",
    )
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in {status!r}"


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s: float = 900.0) -> None:
    """Delete a CFN stack (and its cascaded nested stack) and wait for DELETE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code not in ("StackNotFoundException", "ValidationError") or (
                code == "ValidationError" and "does not exist" not in message
            ):
                raise
            return "GONE"

    final = _poll_until(
        _status, lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
        timeout_s=timeout_s, interval_s=5.0, description=f"delete stack {stack_name}",
    )
    if final == "DELETE_FAILED":
        raise AssertionError(f"stack {stack_name} failed to delete")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the last result or raise."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
