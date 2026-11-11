"""cfn-yaml-short-form-intrinsics-shape-resources."""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-yaml-short-form-intrinsics-shape-resources"

GROUP = "deployment-order"

SERVICES = ["cloudformation", "ec2", "sqs", "ssm"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "cap:c5", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A YAML template using !Ref/!If/!FindInMap/!GetAZs short forms yields live SQS, SSM and EC2
    resources whose properties match the selected branch: the FIFO branch is enforced by SQS's
    MessageGroupId check and the AWS::NoValue KMS property is absent from the queue's attributes."""
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")

    base_name = _xname(ctx, "yamlq")
    label_param = "/" + _xname(ctx, "yaml-label")
    az_param = "/" + _xname(ctx, "yaml-az")
    mode_param = "/" + _xname(ctx, "yaml-mode")
    for name in (label_param, az_param, mode_param):
        ctx.on_cleanup(lambda n=name: _delete_parameter_if_present(ssm, n))

    result = _deploy_cfn(
        ctx,
        (DEPLOYMENTS / "yaml-short-form-intrinsics.yaml").read_text(),
        parameters={
            "QueueBaseName": base_name,
            "LabelParameterName": label_param,
            "AzParameterName": az_param,
            "ModeParameterName": mode_param,
            "Ordering": "ordered",
            "EnableEncryption": "false",
        },
        timeout_s=600.0,
    )
    outputs = _outputs(result)
    queue_url = outputs["QueueUrl"]

    # 1. !If picked the FIFO branch and !Sub built the mandatory .fifo suffix.
    expected_queue_name = f"{base_name}.fifo"
    assert outputs["QueueNameOut"] == expected_queue_name, (
        f"GetAtt QueueName is {outputs['QueueNameOut']!r}, expected {expected_queue_name!r}"
    )
    attributes = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])[
        "Attributes"
    ]
    assert attributes.get("FifoQueue") == "true", (
        f"queue is not FIFO ({attributes.get('FifoQueue')!r}); the !If/!FindInMap branch that "
        "sets FifoQueue was not applied"
    )
    assert attributes.get("ContentBasedDeduplication") == "true", (
        f"ContentBasedDeduplication is {attributes.get('ContentBasedDeduplication')!r}, "
        "expected 'true' on the FIFO branch"
    )

    # 2. It is a real FIFO queue as far as SQS is concerned, not just a flag in a template:
    #    SQS itself rejects a send without MessageGroupId, and accepts one without a
    #    deduplication id only because ContentBasedDeduplication is on.
    _expect_client_error(
        lambda: sqs.send_message(QueueUrl=queue_url, MessageBody="no-group"),
        {"MissingParameter"},
        "send_message to a FIFO queue without MessageGroupId",
        message="The request must contain the parameter MessageGroupId.",
    )
    sqs.send_message(
        QueueUrl=queue_url, MessageBody="grouped", MessageGroupId="sim2real-xsvc-g1"
    )
    received = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: bool(msgs),
        timeout_s=90.0,
        interval_s=2.0,
        description=f"message on {expected_queue_name}",
    )
    assert received[0]["Body"] == "grouped", (
        f"expected body 'grouped' on the message received from {expected_queue_name}, "
        f"got {received[0].get('Body')!r}"
    )

    # 3. !Ref 'AWS::NoValue' must ELIDE the property, not set it empty.
    assert "KmsMasterKeyId" not in attributes, (
        "KmsMasterKeyId is present on the queue; !If [..., !Ref 'AWS::NoValue'] must remove the "
        f"property entirely (attributes: {sorted(attributes)})"
    )

    # 4. !FindInMap supplied a real numeric property value.
    assert outputs["WaitSecondsFromMap"] == "17", (
        f"!FindInMap [OrderingMap, ordered, WaitSeconds] must resolve to '17', got "
        f"{outputs['WaitSecondsFromMap']!r}"
    )
    assert attributes.get("ReceiveMessageWaitTimeSeconds") == "17", (
        f"ReceiveMessageWaitTimeSeconds is {attributes.get('ReceiveMessageWaitTimeSeconds')!r}; "
        "the Mappings lookup for the 'ordered' key returns 17"
    )

    # 5. Pseudo parameters: the ARN built by !Sub must equal the one the service reports.
    assert outputs["ExpectedQueueArn"] == outputs["QueueArn"] == attributes["QueueArn"], (
        f"!Sub-built ARN {outputs['ExpectedQueueArn']!r} != GetAtt Arn {outputs['QueueArn']!r} "
        f"!= SQS-reported {attributes['QueueArn']!r}"
    )

    # 6. !Join + !Select + !Split resolved against the deploy region.
    region = ctx.region
    expected_label = f"ordered-{region.split('-')[1]}"
    label_value = ssm.get_parameter(Name=label_param)["Parameter"]["Value"]
    assert label_value == expected_label, (
        f"the !Join/!Select/!Split parameter holds {label_value!r}, expected {expected_label!r} "
        f"for region {region}"
    )

    # 7. !GetAZs must return this region's real availability zones (an EC2 lookup).
    az_value = ssm.get_parameter(Name=az_param)["Parameter"]["Value"]
    zone_names = [
        z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]
    ]
    assert az_value in zone_names, (
        f"!GetAZs produced {az_value!r}, which EC2 does not list for {region}: {zone_names}"
    )
    assert az_value.startswith(region), (
        f"!GetAZs produced {az_value!r}, which is not in the deploy region {region}"
    )

    # 8. !If selecting its SECOND branch, and a resource-level Condition driven by !Or.
    assert ssm.get_parameter(Name=mode_param)["Parameter"]["Value"] == "plain", (
        "!If [UseKms, encrypted, plain] must resolve to the second branch when the Fn::And "
        "condition is false"
    )
    logical_ids = {
        r["LogicalResourceId"]
        for r in cfn.list_stack_resources(StackName=result["stack_name"])[
            "StackResourceSummaries"
        ]
    }
    assert "LabelParameter" in logical_ids, (
        f"the Fn::Or-conditioned resource was skipped: {sorted(logical_ids)}"
    )

    # 9. Fn::Base64, and Output-level Conditions in both directions.
    assert base64.b64decode(outputs["OrderingBase64"]).decode() == "ordered", (
        f"Fn::Base64 of 'ordered' must decode back to 'ordered', got "
        f"{outputs['OrderingBase64']!r}"
    )
    assert outputs.get("PlainModeNote") == "plain-mode", (
        f"an Output whose Condition is true must be published: {outputs}"
    )
    assert "KmsAliasUsed" not in outputs, (
        f"an Output whose Condition is false must be omitted entirely: {outputs}"
    )

    # 10. Teardown is real, not merely scheduled: delete the stack and parameters now
    #     (on_cleanup's post-run pass over the same idempotent helpers is then a no-op)
    #     and prove it with an independent read that the interpreted resources are gone.
    _delete_stack_and_wait(ctx, result["stack_name"])
    for name in (label_param, az_param, mode_param):
        _delete_parameter_if_present(ssm, name)

    # DescribeStacks by NAME 404s the instant a stack is gone; only the StackId (ARN)
    # keeps resolving to the deleted stack's terminal status.
    deleted_stack = cfn.describe_stacks(StackName=result["stack_id"])["Stacks"][0]
    assert deleted_stack["StackStatus"] == "DELETE_COMPLETE", (
        f"stack {result['stack_id']!r} must reach DELETE_COMPLETE after delete_stack, got "
        f"{deleted_stack['StackStatus']!r}"
    )
    for name in (label_param, az_param, mode_param):
        _expect_client_error(
            lambda n=name: ssm.get_parameter(Name=n),
            {"ParameterNotFound"},
            f"get_parameter on the deleted parameter {name}",
            message=_PARAMETER_NOT_FOUND_MESSAGE,
        )
    _expect_client_error(
        lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]),
        {"QueueDoesNotExist", "AWS.SimpleQueueService.NonExistentQueue"},
        "get_queue_attributes on the queue after stack deletion",
        message="The specified queue does not exist.",
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_PARAMETER_NOT_FOUND_MESSAGE = ""  # SSM sends ParameterNotFound with an empty message

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _outputs(result: dict) -> dict:
    """Deployment results may nest outputs under 'outputs' or expose them flat."""
    return result.get("outputs", result)


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _expect_client_error(fn, codes, description, *, message):
    """Require fn() to raise ClientError with an Error.Code in codes and exactly `message`;
    return the code."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        assert code in codes, (
            f"{description}: expected error code in {sorted(codes)}, got {code!r} ({exc})"
        )
        got = exc.response.get("Error", {}).get("Message")
        assert got == message, f"{description}: expected message {message!r}, got {got!r}"
        return code
    raise AssertionError(f"{description}: call unexpectedly succeeded")


def _delete_parameter_if_present(ssm, name: str) -> None:
    """Best-effort SSM parameter teardown; already-deleted is not an error."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=600.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE; any other failure raises."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" not in str(exc):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=600.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=timeout_s))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
