"""sar-change-set-deploys-functioning-queue."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sar-change-set-deploys-functioning-queue"
GROUP = 'deploy-sar-changeset'
SERVICES = ['cloudformation', 'serverlessrepo', 'sqs']

# The application's own SAM template. QueueVisibility exists so the deploy can be driven with a
# ParameterOverride that differs from the default, which is how this check proves the override
# reached the provisioned resource rather than merely the change set.
_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Parameters:
  QueueVisibility:
    Type: Number
    Default: 30
Resources:
  Q:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: !Ref QueueVisibility
Outputs:
  QueueUrl:
    Value: !Ref Q
  QueueArn:
    Value: !GetAtt Q.Arn
"""

_TEMPLATE_DEFAULT_VISIBILITY = "30"
_OVERRIDE_VISIBILITY = "77"


#: How long a teardown waits for an issued delete to finish: a one-queue stack and its SAR
#: application delete well within it, and all teardowns together fit the cleanup budget.
_CONFIRM_DELETE_S = 300.0


def _ignore_not_found(fn):
    """Run fn, treating an already-gone target as success and retrying a refusal briefly.

    SAR refuses to delete an application while a stack it planned is still being torn down.
    """
    deadline = time.time() + _CONFIRM_DELETE_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if time.time() >= deadline:
                raise RuntimeError(f"teardown could not complete: {code}: {exc}") from exc
            time.sleep(3)


def _delete_stack(cfn, stack_id):
    """Delete the stack SAR created (`serverlessrepo-<requested>`) and wait for it to finish,
    bounded by _CONFIRM_DELETE_S; a stack still deleting at the deadline raises."""
    try:
        cfn.delete_stack(StackName=stack_id)
    except ClientError as exc:
        raise RuntimeError(f"delete_stack({stack_id}) failed: {exc}") from exc
    deadline = time.time() + _CONFIRM_DELETE_S
    while time.time() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as err:
            if not (
                err.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in err.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_id} reached DELETE_FAILED")
        time.sleep(2)
    raise TimeoutError(f"stack {stack_id} still deleting after {_CONFIRM_DELETE_S:.0f}s")


@tags(
    "axis:happy-path",
    "concern:deploy",
    "concern:data-plane",
    "concern:e2e",
    "plane:data",
    "dp:api",
    "cap:c1",
)
def run(ctx) -> None:
    """A SAR change set is an empty REVIEW_IN_PROGRESS plan until executed; executing it deploys
    the queue, tags the stack with SAR provenance, applies the parameter override to the live queue,
    and the queue round-trips a message.
    """
    sar = ctx.client("serverlessrepo")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    app_name = ctx.unique_name("sim2real-xsvc-sar-")
    app_id = sar.create_application(
        Name=app_name, Author="sim2real xsvc", Description="sar change set deploy",
        SemanticVersion="1.0.0", TemplateBody=_TEMPLATE,
    )["ApplicationId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sar.delete_application(ApplicationId=app_id)))

    requested_stack = ctx.unique_name("sim2real-xsvc-sar-")
    change_set = sar.create_cloud_formation_change_set(
        ApplicationId=app_id, SemanticVersion="1.0.0", StackName=requested_stack,
        Capabilities=[],
        ParameterOverrides=[{"Name": "QueueVisibility", "Value": _OVERRIDE_VISIBILITY}],
    )
    stack_id = change_set["StackId"]
    change_set_id = change_set["ChangeSetId"]
    # Registered before the execute, because creating the change set is already what created the
    # (empty) stack — an unexecuted change set leaves a REVIEW_IN_PROGRESS stack behind.
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))

    assert ":changeSet/" in change_set_id, (
        f"SAR returned ChangeSetId {change_set_id!r}, which is not a CloudFormation change-set ARN"
    )
    assert change_set["SemanticVersion"] == "1.0.0", (
        f"the change set names version {change_set['SemanticVersion']!r}, expected 1.0.0"
    )
    # SAR does not require the caller to pre-prefix the stack name; it PREPENDS its own namespace.
    expected_stack_name = f"serverlessrepo-{requested_stack}"
    assert stack_id.split("/")[1] == expected_stack_name, (
        f"SAR created stack {stack_id.split('/')[1]!r} for requested name {requested_stack!r}; "
        f"expected {expected_stack_name!r} — SAR namespaces the stack it deploys into"
    )

    deadline = time.time() + 300
    described = cfn.describe_change_set(ChangeSetName=change_set_id)
    while described["Status"] == "CREATE_PENDING" or described["Status"] == "CREATE_IN_PROGRESS":
        assert time.time() < deadline, (
            f"change set {change_set_id!r} was still {described['Status']!r} after 300s"
        )
        time.sleep(3)
        described = cfn.describe_change_set(ChangeSetName=change_set_id)
    assert described["Status"] == "CREATE_COMPLETE", (
        f"change set reached Status {described['Status']!r} "
        f"({described.get('StatusReason')!r}), expected CREATE_COMPLETE"
    )
    assert described["ExecutionStatus"] == "AVAILABLE", (
        f"change set reported ExecutionStatus {described['ExecutionStatus']!r}, expected AVAILABLE "
        f"— a plan that cannot be executed is not a deployable change set"
    )
    assert [(c["ResourceChange"]["Action"], c["ResourceChange"]["ResourceType"],
             c["ResourceChange"]["LogicalResourceId"]) for c in described["Changes"]] == [
        ("Add", "AWS::SQS::Queue", "Q")
    ], (
        f"the change set plans {described['Changes']!r}; expected exactly one Add of the "
        f"AWS::SQS::Queue logical resource Q that the application's template declares"
    )
    assert described["Parameters"] == [
        {"ParameterKey": "QueueVisibility", "ParameterValue": _OVERRIDE_VISIBILITY}
    ], (
        f"the change set carries parameters {described['Parameters']!r}; the override "
        f"{_OVERRIDE_VISIBILITY!r} must replace the template default "
        f"{_TEMPLATE_DEFAULT_VISIBILITY!r}"
    )
    # SAR asks CloudFormation for CAPABILITY_IAM unconditionally — this template creates no IAM at
    # all and the CreateCloudFormationChangeSet request above passed Capabilities=[].
    assert described["Capabilities"] == ["CAPABILITY_IAM"], (
        f"the change set declares capabilities {described['Capabilities']!r}; SAR requests "
        f"['CAPABILITY_IAM'] even for a template that needs none and a request that asked for none"
    )

    # Before execution the change set is a PLAN: the stack exists but holds nothing.
    pre = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert pre["StackStatus"] == "REVIEW_IN_PROGRESS", (
        f"before execution the stack is {pre['StackStatus']!r}, expected REVIEW_IN_PROGRESS"
    )
    assert pre["Tags"] == [], (
        f"the unexecuted stack already carries tags {pre['Tags']!r}; SAR stamps its provenance at "
        f"deploy time, not at change-set creation"
    )
    assert cfn.describe_stack_resources(StackName=stack_id)["StackResources"] == [], (
        "the unexecuted stack already holds resources; a change set must not provision anything "
        "until it is executed"
    )

    cfn.execute_change_set(ChangeSetName=change_set_id)
    deadline = time.time() + 900
    deployed = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    while deployed["StackStatus"] in ("REVIEW_IN_PROGRESS", "CREATE_IN_PROGRESS"):
        assert time.time() < deadline, (
            f"stack {stack_id!r} was still {deployed['StackStatus']!r} after 900s"
        )
        time.sleep(5)
        deployed = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert deployed["StackStatus"] == "CREATE_COMPLETE", (
        f"executing the change set left the stack {deployed['StackStatus']!r} "
        f"({deployed.get('StackStatusReason')!r}), expected CREATE_COMPLETE"
    )

    # SAR's provenance, written onto the CloudFormation stack by the deploy.
    stack_tags = {t["Key"]: t["Value"] for t in deployed["Tags"]}
    assert stack_tags == {"serverlessrepo:applicationId": app_id,
                          "serverlessrepo:semanticVersion": "1.0.0"}, (
        f"the deployed stack carries tags {stack_tags!r}; SAR stamps exactly the application ARN "
        f"and the deployed semantic version onto the stack it creates"
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in deployed["Outputs"]}
    assert sorted(outputs) == ["QueueArn", "QueueUrl"], (
        f"the deployed stack exposes outputs {sorted(outputs)!r}, expected the template's "
        f"QueueArn and QueueUrl"
    )
    queue_url = outputs["QueueUrl"]

    # The override survived SAR -> CloudFormation -> SQS and governs the LIVE resource, not just
    # the plan: a deploy that dropped it would report the template default instead.
    attributes = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["VisibilityTimeout", "QueueArn"],
    )["Attributes"]
    assert attributes["VisibilityTimeout"] == _OVERRIDE_VISIBILITY, (
        f"the deployed queue reports VisibilityTimeout {attributes['VisibilityTimeout']!r}; the "
        f"ParameterOverride {_OVERRIDE_VISIBILITY!r} must reach the resource, not the template "
        f"default {_TEMPLATE_DEFAULT_VISIBILITY!r}"
    )
    assert attributes["QueueArn"] == outputs["QueueArn"], (
        f"the queue's own ARN {attributes['QueueArn']!r} disagrees with the stack output "
        f"{outputs['QueueArn']!r}"
    )

    payload = f"sim2real-xsvc-sar-{app_name}-payload"
    sent = sqs.send_message(QueueUrl=queue_url, MessageBody=payload)
    assert sent["MessageId"], "send_message to the deployed queue returned no MessageId"

    received = None
    deadline = time.time() + 60
    while received is None and time.time() < deadline:
        batch = sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=5, MaxNumberOfMessages=1,
        ).get("Messages", [])
        if batch:
            received = batch[0]
    assert received is not None, (
        f"the payload sent to the deployed queue {queue_url!r} never came back within 60s"
    )
    assert received["Body"] == payload, (
        f"the deployed queue returned body {received['Body']!r}, expected {payload!r}"
    )
    assert received["MessageId"] == sent["MessageId"], (
        f"the queue returned MessageId {received['MessageId']!r} for the message sent as "
        f"{sent['MessageId']!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
