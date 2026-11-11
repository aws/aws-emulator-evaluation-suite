"""rds-ssm-secure-dynamic-reference-misuse-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-ssm-secure-dynamic-reference-misuse-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "rds", "ssm"]


def _template(master_username, master_password) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Database": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {
                        "DBInstanceClass": "db.t3.micro",
                        "AllocatedStorage": "20",
                        "Engine": "postgres",
                        "MasterUsername": master_username,
                        "MasterUserPassword": master_password,
                    },
                    "DeletionPolicy": "Delete",
                }
            },
        }
    )


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CloudFormation rejects `{{resolve:ssm-secure:...}}` on a plain String parameter and on the DB
    instance's admin user name, rolling back before RDS is called; the same resolver on the admin
    password gets through to RDS creating the instance."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    rds = ctx.client("rds")

    plain_param = ctx.unique_name("sim2real-xsvc-plainpw-")
    secure_param = ctx.unique_name("sim2real-xsvc-secureuser-")

    ssm.put_parameter(Name=plain_param, Value="plainTextPassword123", Type="String")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=plain_param))
    ssm.put_parameter(Name=secure_param, Value="produser", Type="SecureString")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=secure_param))

    # Negative 1: a plain String parameter resolved through the ssm-secure prefix.
    stack1 = ctx.unique_name("sim2real-xsvc-stk-")
    cfn.create_stack(
        StackName=stack1,
        TemplateBody=_template("produser", f"{{{{resolve:ssm-secure:{plain_param}}}}}"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack1))
    stack = _wait_terminal(cfn, stack1, timeout_s=120.0)
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE for a plain param used via ssm-secure, got {stack['StackStatus']!r}"
    )
    reason1 = _resource_failure_reason(cfn, stack1, stack1)
    assert reason1 is not None and "ssm-secure prefix was used for non-secure parameter" in reason1, (
        f"expected the ssm-secure/non-secure-parameter reason, got {reason1!r}"
    )

    # Negative 2: a genuine SecureString resolved through ssm-secure, but on the admin user name.
    # ssm-secure resolves only on an allowlist of properties, which excludes the user name.
    stack2 = ctx.unique_name("sim2real-xsvc-stk-")
    cfn.create_stack(
        StackName=stack2,
        TemplateBody=_template(f"{{{{resolve:ssm-secure:{secure_param}}}}}", "PlainPassw0rd123"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack2))
    stack = _wait_terminal(cfn, stack2, timeout_s=120.0)
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE for ssm-secure used on MasterUsername, got {stack['StackStatus']!r}"
    )
    reason2 = _resource_failure_reason(cfn, stack2, stack2)
    assert reason2 is not None and "SSM Secure reference is not supported" in reason2 and (
        "MasterUsername" in reason2
    ), f"expected the MasterUsername-not-supported reason, got {reason2!r}"

    # Positive control: the SAME resolver, used correctly on the admin password against a real
    # SecureString, is NOT rejected -- it clears CloudFormation's gate and RDS genuinely starts
    # creating the instance.
    stack3 = ctx.unique_name("sim2real-xsvc-stk-")
    cfn.create_stack(
        StackName=stack3,
        TemplateBody=_template("produser", f"{{{{resolve:ssm-secure:{secure_param}}}}}"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack3))
    initiated = _poll_until(
        lambda: _resource_status_and_reason(cfn, stack3, "Database"),
        lambda sr: sr[1] == "Resource creation Initiated" or sr[0] not in {"CREATE_IN_PROGRESS", None},
        timeout_s=60.0,
        description="Database resource to start real creation",
    )
    assert initiated[1] == "Resource creation Initiated", (
        "a correctly-used ssm-secure reference on MasterUserPassword must clear CloudFormation's "
        f"own gate and reach real RDS creation, got status={initiated[0]!r} reason={initiated[1]!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _resource_status_and_reason(cfn, stack_name: str, logical_id: str):
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except ClientError:
        return (None, None)
    for e in events:
        if e["LogicalResourceId"] == logical_id:
            return (e["ResourceStatus"], e.get("ResourceStatusReason"))
    return (None, None)


def _resource_failure_reason(cfn, stack_name: str, logical_id: str):
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for e in events:
        if e["LogicalResourceId"] == logical_id and e.get("ResourceStatusReason"):
            return e["ResourceStatusReason"]
    return None


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 3.0):
    terminal = {
        "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
        "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    }
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        last = stacks[0]
        if last["StackStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if not status.endswith("IN_PROGRESS"):
            break
        time.sleep(interval_s)
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
