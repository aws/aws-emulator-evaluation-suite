"""deploy-sar-published-version-changeset-into-a-working-queue."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sar-published-version-changeset-into-a-working-queue"
GROUP = "deploy-serverlessrepo-changeset"
SERVICES = ["cloudformation", "serverlessrepo", "sqs"]

# The change set itself is prepared in ~6s, but EXECUTING it provisions a real queue through
# CloudFormation and then tears the stack down again, so the whole check needs a minute-scale
# budget rather than the light-check default.
_STACK_WAIT_S = 600
# Cleanups share one 60s bound, so teardown observes the delete rather than waiting it out.
_DELETE_OBSERVE_S = 20
_CHANGE_SET_WAIT_S = 180

# A published SAR application version must carry a Transform (a plain CloudFormation body is
# rejected at CreateApplicationVersion with "Resource must have Transform field"), so the
# published artifact is SAM and SAR's own template renderer is part of what this check grades.
_SAM_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Transform": "AWS::Serverless-2016-10-31",
    "Parameters": {"QueueNameParam": {"Type": "String"}},
    "Resources": {
        "Q": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": {"Ref": "QueueNameParam"}},
        }
    },
    "Outputs": {
        "QueueUrl": {"Value": {"Ref": "Q"}},
        "QueueArn": {"Value": {"Fn::GetAtt": ["Q", "Arn"]}},
    },
}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A SAR change set on a published version targets a `serverlessrepo-`-prefixed stack, creates
    nothing until executed, then deploys the queue with the parameter override and SAR's
    provenance tags, and the queue round-trips a message."""
    sar = ctx.client("serverlessrepo")
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    app_name = ctx.unique_name("sim2real-xsvc-sarapp-")
    created = sar.create_application(
        Name=app_name,
        Author="sim2real-xsvc",
        Description="sim2real cross-service SAR deploy check",
        TemplateBody=json.dumps(_SAM_TEMPLATE),
        SemanticVersion="1.0.0",
    )
    app_id = created["ApplicationId"]
    ctx.on_cleanup(lambda: sar.delete_application(ApplicationId=app_id))
    assert created["Version"]["SemanticVersion"] == "1.0.0", (
        f"published version is {created['Version']['SemanticVersion']!r}"
    )
    assert created["Version"]["ResourcesSupported"] is True, (
        f"SAR reports the published resources unsupported: {created['Version']!r}"
    )

    stack_name = ctx.unique_name("sim2real-xsvc-sarstk-")
    queue_name = ctx.unique_name("sim2real-xsvc-sarq-")
    change_set = sar.create_cloud_formation_change_set(
        ApplicationId=app_id,
        StackName=stack_name,
        SemanticVersion="1.0.0",
        ParameterOverrides=[{"Name": "QueueNameParam", "Value": queue_name}],
    )
    stack_id = change_set["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))

    # SAR does not deploy into the stack name you asked for: it owns the namespace and prefixes it.
    expected_stack_name = f"serverlessrepo-{stack_name}"
    assert f":stack/{expected_stack_name}/" in stack_id, (
        f"StackId {stack_id!r} does not name a stack called {expected_stack_name!r}"
    )
    assert change_set["ApplicationId"] == app_id, (
        f"change set reports application {change_set['ApplicationId']!r}, published {app_id!r}"
    )
    assert change_set["SemanticVersion"] == "1.0.0", (
        f"change set reports version {change_set['SemanticVersion']!r}"
    )

    described = _await_change_set(cfn, change_set["ChangeSetId"])
    assert described["Status"] == "CREATE_COMPLETE", (
        f"change set is {described['Status']!r}: {described.get('StatusReason')!r}"
    )
    assert described["ExecutionStatus"] == "AVAILABLE", (
        f"change set is not executable: ExecutionStatus={described['ExecutionStatus']!r}"
    )
    assert described["StackName"] == expected_stack_name, (
        f"change set targets stack {described['StackName']!r}, expected {expected_stack_name!r}"
    )

    # The SAM transform ran: exactly one resource is added, and it is the queue the template
    # describes under its own logical id.
    changes = [
        (c["ResourceChange"]["Action"],
         c["ResourceChange"]["LogicalResourceId"],
         c["ResourceChange"]["ResourceType"])
        for c in described["Changes"]
        if c["Type"] == "Resource"
    ]
    assert changes == [("Add", "Q", "AWS::SQS::Queue")], f"unexpected changes {changes!r}"

    overrides = {p["ParameterKey"]: p["ParameterValue"] for p in described["Parameters"]}
    assert overrides == {"QueueNameParam": queue_name}, (
        f"parameter overrides did not survive into the change set: {overrides!r}"
    )

    # A change set is a plan. Nothing exists yet.
    pre_execute, pre_message = _error(lambda: sqs.get_queue_url(QueueName=queue_name))
    assert pre_execute == "AWS.SimpleQueueService.NonExistentQueue", (
        f"queue {queue_name!r} already resolves ({pre_execute!r}) before the change set was "
        "executed"
    )
    assert pre_message == "The specified queue does not exist.", (
        f"get_queue_url message {pre_message!r} != 'The specified queue does not exist.'"
    )

    cfn.execute_change_set(ChangeSetName=change_set["ChangeSetId"])
    stack = _await_stack(cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack is {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    assert stack["StackName"] == expected_stack_name, (
        f"executed stack is named {stack['StackName']!r}, expected {expected_stack_name!r}"
    )

    stack_tags = {t["Key"]: t["Value"] for t in stack.get("Tags", [])}
    assert stack_tags.get("serverlessrepo:applicationId") == app_id, (
        f"stack does not carry SAR's application provenance tag: {stack_tags!r}"
    )
    assert stack_tags.get("serverlessrepo:semanticVersion") == "1.0.0", (
        f"stack does not carry SAR's version provenance tag: {stack_tags!r}"
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert sorted(outputs) == ["QueueArn", "QueueUrl"], (
        f"published outputs did not reach the stack: {sorted(outputs)!r}"
    )
    assert outputs["QueueUrl"].endswith(f"/{queue_name}"), (
        f"deployed queue url {outputs['QueueUrl']!r} does not end in {queue_name!r}"
    )
    assert outputs["QueueArn"].endswith(f":{queue_name}"), (
        f"deployed queue arn {outputs['QueueArn']!r} does not end in {queue_name!r}"
    )

    # Deployed means functional: the queue the published application described round-trips a body.
    payload = f"sim2real-xsvc-sar-{queue_name}"
    sqs.send_message(QueueUrl=outputs["QueueUrl"], MessageBody=payload)
    received = _receive_one(sqs, outputs["QueueUrl"])
    assert received == payload, (
        f"deployed queue returned {received!r}, sent {payload!r}"
    )


def _error(fn) -> tuple[str, str | None]:
    """(code, message) of the ClientError fn() raises. RAISES if fn() succeeds."""
    try:
        ok = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it succeeded and returned {ok!r}")


def _await_change_set(cfn, change_set_id: str) -> dict:
    deadline = time.time() + _CHANGE_SET_WAIT_S
    described = cfn.describe_change_set(ChangeSetName=change_set_id)
    while described["Status"] in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
        assert time.time() < deadline, (
            f"change set {change_set_id!r} stuck in {described['Status']!r} after "
            f"{_CHANGE_SET_WAIT_S}s"
        )
        time.sleep(3)
        described = cfn.describe_change_set(ChangeSetName=change_set_id)
    return described


def _await_stack(cfn, stack_id: str) -> dict:
    deadline = time.time() + _STACK_WAIT_S
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    while stack["StackStatus"].endswith("_IN_PROGRESS"):
        assert time.time() < deadline, (
            f"stack {stack_id!r} stuck in {stack['StackStatus']!r} after {_STACK_WAIT_S}s"
        )
        time.sleep(5)
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return stack


def _receive_one(sqs, queue_url: str) -> str | None:
    deadline = time.time() + 60
    while time.time() < deadline:
        got = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        for message in got.get("Messages", []):
            return message["Body"]
    return None


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack, waiting only until CloudFormation has started the delete: cleanups share
    one 60s bound and run LIFO, and the application delete registered earlier must still run."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.time() + _DELETE_OBSERVE_S
    while time.time() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_id)["Stacks"]
        if stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        if stacks[0]["StackStatus"] == "DELETE_FAILED":
            raise AssertionError(
                f"stack {stack_id!r} failed to delete: {stacks[0].get('StackStatusReason')!r}"
            )
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
