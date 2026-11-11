"""deploy-app-monitor-cfn-tags-propagate."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-app-monitor-cfn-tags-propagate"
GROUP = "deploy"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags declared on a CloudFormation AWS::RUM::AppMonitor are returned by ListTagsForResource,
    proving CFN wired them to the live resource, and the same read returns NotFoundException
    once the stack that created the app monitor is deleted."""
    name = ctx.unique_name("sim2real-rum-cfn-tags-")
    template = f"""
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  AppMonitor:
    Type: AWS::RUM::AppMonitor
    Properties:
      Name: {name}
      Domain: localhost
      Tags:
        - Key: sim2real-env
          Value: behavioral
        - Key: sim2real-owner
          Value: rum-suite
"""

    cfn, stack_name = _deploy_cfn(ctx, template)

    rum = ctx.client("rum")
    arn = _app_monitor_arn(ctx, name)
    live_tags = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert live_tags.get("sim2real-env") == "behavioral", live_tags
    assert live_tags.get("sim2real-owner") == "rum-suite", live_tags

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    # ListTagsForResource on the now-deleted app monitor may lag the stack's own
    # DELETE_COMPLETE by a beat; poll rather than asserting at the exact boundary.
    code, message = _poll_for_error(
        lambda: rum.list_tags_for_resource(ResourceArn=arn), timeout_s=30.0, interval_s=3.0
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException from ListTagsForResource once the stack-created "
        f"app monitor was deleted, got {code!r}"
    )
    assert message == "Resource was not found", message


def _deploy_cfn(ctx, template_body: str):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rum-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack["StackStatus"]
    return cfn, stack_name


def _delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 28}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name: str) -> str:
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, because
    a target accepting a call real AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_for_error(fn, *, timeout_s: float, interval_s: float):
    """Poll until fn() is refused; return the (code, message). A success keeps polling until the
    deadline, then raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _client_error(fn)
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"call was not refused within {timeout_s}s: {exc}") from None
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
