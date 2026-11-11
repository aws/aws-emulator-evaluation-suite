"""deploy-notebook-instance-cfn-behaves."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-notebook-instance-cfn-behaves"
GROUP = "deploy"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::SageMaker::NotebookInstance reaches InService with the stack's role and ARN and a presigned
    URL naming it; a URL for a missing instance is refused with ValidationException (exact message), and after stack
    deletion DescribeNotebookInstance answers ValidationException "RecordNotFound".
    """
    iam = ctx.client("iam")
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")

    role_name = ctx.unique_name("sim2real-sm-nb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_tags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real-check", "Value": CHECK},
    ]
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=role_tags,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
    )

    notebook_name = ctx.unique_name("sim2real-sm-nb-")
    stack_name = ctx.unique_name("sim2real-sm-nb-stack-")
    template = json.dumps(
        {
            "Parameters": {
                "NotebookName": {"Type": "String"},
                "RoleArn": {"Type": "String"},
            },
            "Resources": {
                "Notebook": {
                    "Type": "AWS::SageMaker::NotebookInstance",
                    "Properties": {
                        "NotebookInstanceName": {"Ref": "NotebookName"},
                        "InstanceType": "ml.t3.medium",
                        "RoleArn": {"Ref": "RoleArn"},
                    },
                }
            },
            "Outputs": {
                "NotebookArn": {"Value": {"Fn::GetAtt": ["Notebook", "NotebookInstanceArn"]}}
            },
        }
    )
    stack_tags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real-check", "Value": CHECK},
    ]

    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _create_stack_with_role_propagation_retry(
        ctx,
        cfn,
        stack_name,
        template,
        parameters=[
            {"ParameterKey": "NotebookName", "ParameterValue": notebook_name},
            {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
        ],
        tags=stack_tags,
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }

    # Stack CREATE_COMPLETE for this resource type already implies SageMaker
    # finished provisioning, but poll DescribeNotebookInstance directly so we
    # assert the state-machine outcome, not merely the CFN wrapper's opinion.
    described = _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=notebook_name),
        lambda d: d["NotebookInstanceStatus"] in ("InService", "Failed"),
        timeout_s=600,
        interval_s=10,
    )
    assert described["NotebookInstanceStatus"] == "InService", (
        f"notebook instance ended in status {described['NotebookInstanceStatus']}, "
        f"not InService (failure reason: {described.get('FailureReason')})"
    )
    assert described["RoleArn"] == role_arn, (
        f"expected notebook instance RoleArn {role_arn!r}, got {described['RoleArn']!r}"
    )
    assert outputs.get("NotebookArn") == described["NotebookInstanceArn"], (
        f"CFN output NotebookArn {outputs.get('NotebookArn')!r} does not match the "
        f"instance's own reported ARN {described['NotebookInstanceArn']!r}"
    )

    presigned = sm.create_presigned_notebook_instance_url(NotebookInstanceName=notebook_name)
    url = presigned["AuthorizedUrl"]
    assert url.startswith("https://"), url
    assert notebook_name in url, url
    assert "authToken=" in url, url

    # Overly-permissive check: CreatePresignedNotebookInstanceUrl for a
    # nonexistent notebook instance name must fail with ValidationException naming the
    # missing instance -- a lenient emulator that hands back a presigned URL for any name
    # (real or not) would be overly permissive.
    missing_name = ctx.unique_name("sim2real-sm-nb-missing-")
    try:
        sm.create_presigned_notebook_instance_url(NotebookInstanceName=missing_name)
        raise AssertionError(
            "CreatePresignedNotebookInstanceUrl for a nonexistent notebook instance "
            "unexpectedly succeeded"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ValidationException", (
            f"expected ValidationException for nonexistent notebook instance, got {code}: {message}"
        )
        account = described["NotebookInstanceArn"].split(":")[4]
        expected = (
            f"Notebook Instance arn:aws:sagemaker:{ctx.region}:{account}:notebook-instance/"
            f"{missing_name} does not exist"
        )
        assert message == expected, f"expected {expected!r}, got {message!r}"

    # Teardown is asserted, not just performed: deleting the stack must actually make the
    # notebook instance gone at an independent read, not merely report DELETE_COMPLETE.
    _delete_stack(ctx, stack_name)
    gone_code, gone_message = _describe_refusal(sm, notebook_name, timeout_s=120, interval_s=2)
    assert gone_code == "ValidationException", (
        f"expected ValidationException reading the deleted notebook instance "
        f"{notebook_name!r}, got {gone_code!r}"
    )
    assert gone_message == "RecordNotFound", f"expected 'RecordNotFound', got {gone_message!r}"


# ===== helpers =====


def _describe_refusal(sm, name: str, *, timeout_s: float, interval_s: float) -> tuple[str, str]:
    """Poll DescribeNotebookInstance until it refuses and return the refusal's (code, message); a
    describe that still succeeds at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            described = sm.describe_notebook_instance(NotebookInstanceName=name)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected {name!r} to be gone, but it still describes: {described!r}")
        time.sleep(interval_s)


def _create_stack_with_role_propagation_retry(
    ctx,
    cfn,
    stack_name: str,
    template: str,
    *,
    parameters: list[dict],
    tags: list[dict],
    max_attempts: int = 3,
) -> None:
    """A freshly-created IAM role is eventually consistent; CloudFormation can attempt to
    provision the AWS::SageMaker::NotebookInstance before the role has propagated, which fails
    the whole stack. There is no API-observable "role ready" signal short of trying it (see
    https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency),
    so retry the stack create itself -- gated on the rollback reason actually naming the role,
    and bounded by attempt count -- rather than guessing a fixed delay."""
    last_exc: AssertionError | None = None
    for attempt in range(1, max_attempts + 1):
        cfn.create_stack(
            StackName=stack_name, TemplateBody=template, Parameters=parameters, Tags=tags
        )
        try:
            _wait_for_stack_status(
                ctx,
                stack_name,
                success_statuses={"CREATE_COMPLETE"},
                failure_statuses={"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_IN_PROGRESS"},
                timeout_s=900,
            )
            return
        except AssertionError as exc:
            last_exc = exc
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            reasons = " ".join(e.get("ResourceStatusReason", "") for e in events).lower()
            _delete_stack(ctx, stack_name)
            if "role" not in reasons or attempt == max_attempts:
                raise
    raise last_exc  # pragma: no cover -- loop always returns or raises above


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _wait_for_stack_status(
    ctx,
    stack_name: str,
    *,
    success_statuses: set[str],
    failure_statuses: set[str],
    timeout_s: float = 600,
    interval_s: float = 10,
) -> str:
    cfn = ctx.client("cloudformation")

    def _status() -> str:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]

    deadline = time.monotonic() + timeout_s
    status = _status()
    while time.monotonic() < deadline:
        status = _status()
        if status in success_statuses:
            return status
        if status in failure_statuses:
            raise AssertionError(f"stack {stack_name} entered failure status {status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {success_statuses} within {timeout_s}s "
        f"(last status: {status})"
    )


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
