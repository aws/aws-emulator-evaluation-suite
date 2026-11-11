"""import-stacks-to-stackset-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-stacks-to-stackset-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """Importing an existing stack into a stack set creates a manageable instance that
    is subsequently updatable via stack instance operations."""
    cfn = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    admin_arn, exec_role_name = _create_stackset_roles(ctx)

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"Note": {"Type": "String", "Default": "orig"}},
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": {"Ref": "Note"}}}
            },
        }
    )

    stack_name = ctx.unique_name("sim2real-import-")
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=template, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    ss_name = ctx.unique_name("sim2real-importss-")
    cfn.create_stack_set(
        StackSetName=ss_name,
        TemplateBody=template,
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cfn, ss_name))

    # The admin/exec roles were just created. IAM's propagation to the point where StackSets can
    # assume them is eventually consistent, and that shows up two ways: the *submit* call itself
    # can 400/403 transiently (caught by _retry_role_propagation below), or the submit succeeds
    # but the *async* StackSetOperation it starts fails while role assumption is not yet live.
    # So the whole submit-and-await cycle is retried, bounded, on that async failure too.
    import_status, import_op = None, None
    deadline = time.monotonic() + min(300.0, ctx.time_left())
    while True:
        import_op = _retry_role_propagation(
            lambda: cfn.import_stacks_to_stack_set(StackSetName=ss_name, StackIds=[stack_id])["OperationId"]
        )
        import_status = _wait_operation(cfn, ss_name, import_op)
        if import_status == "SUCCEEDED" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert import_status == "SUCCEEDED", (import_status, _operation_results(cfn, ss_name, import_op))

    instance = cfn.describe_stack_instance(
        StackSetName=ss_name, StackInstanceAccount=account, StackInstanceRegion=region
    )["StackInstance"]
    assert instance["Status"] == "CURRENT", instance
    assert instance["StackId"] == stack_id, "import should manage the *existing* stack, not create a new one"

    update_op = cfn.update_stack_instances(
        StackSetName=ss_name,
        Accounts=[account],
        Regions=[region],
        ParameterOverrides=[{"ParameterKey": "Note", "ParameterValue": "updated-by-stackset"}],
    )["OperationId"]
    update_status = _wait_operation(cfn, ss_name, update_op)
    assert update_status == "SUCCEEDED", update_status

    updated_instance = cfn.describe_stack_instance(
        StackSetName=ss_name, StackInstanceAccount=account, StackInstanceRegion=region
    )["StackInstance"]
    overrides = {p["ParameterKey"]: p["ParameterValue"] for p in updated_instance.get("ParameterOverrides", [])}
    assert overrides.get("Note") == "updated-by-stackset", updated_instance

    # detach (retain the underlying stack) before the stack-set gets deleted in cleanup
    detach_op = cfn.delete_stack_instances(
        StackSetName=ss_name, Accounts=[account], Regions=[region], RetainStacks=True
    )["OperationId"]
    detach_status = _wait_operation(cfn, ss_name, detach_op)
    assert detach_status == "SUCCEEDED", detach_status

    # the instance is gone from the stack set (independent read) ...
    not_found = _error(
        lambda: cfn.describe_stack_instance(
            StackSetName=ss_name, StackInstanceAccount=account, StackInstanceRegion=region
        )
    )
    expected = ("StackInstanceNotFoundException", "StackInstance not found")
    assert not_found == expected, f"DescribeStackInstance after detach: expected {expected!r}, got {not_found!r}"

    # ... but RetainStacks=True means the underlying stack itself was not touched.
    retained_stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert retained_stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"RetainStacks=True should have left the stack standing, got {retained_stack['StackStatus']}"
    )


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an accepted call raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _retry_on_codes(fn, codes, attempts=8, delay_s=5.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if exc.response.get("Error", {}).get("Code") not in codes:
                raise
            time.sleep(delay_s)
    raise last_exc


def _retry_role_propagation(fn, attempts=8, delay_s=5.0):
    return _retry_on_codes(fn, {"AccessDenied", "ValidationError", "InvalidOperationException"}, attempts, delay_s)


def _operation_results(cfn, ss_name, op_id):
    return cfn.list_stack_set_operation_results(StackSetName=ss_name, OperationId=op_id).get("Summaries", [])


def _wait_stack_status(cfn, stack_name, terminal_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_name} did not reach {terminal_statuses}, last={status}")
        time.sleep(interval_s)


def _wait_operation(cfn, ss_name, op_id, timeout_s=420.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)["StackSetOperation"]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return status
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack set operation {op_id} did not finish, last={status}")
        time.sleep(interval_s)


def _create_stackset_roles(ctx):
    """Per-run StackSets administration and execution roles with inline policies, each torn down."""
    iam = ctx.client("iam")
    role_tags = [{"Key": "sim2real-check", "Value": CHECK}]
    admin_name = ctx.unique_name("sim2real-ss-admin-")
    exec_name = ctx.unique_name("sim2real-ss-exec-")

    admin_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    admin_arn = iam.create_role(
        RoleName=admin_name, AssumeRolePolicyDocument=admin_trust, Tags=role_tags
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=admin_name), "NoSuchEntity"))

    exec_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_arn}, "Action": "sts:AssumeRole"}],
        }
    )
    # IAM's principal validation on CreateRole is eventually consistent for a role created moments
    # ago, so referencing it as a Principal can transiently 400 with MalformedPolicyDocument.
    exec_arn = _retry_on_codes(
        lambda: iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=exec_trust, Tags=role_tags),
        {"MalformedPolicyDocument"},
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=exec_name), "NoSuchEntity"))

    iam.put_role_policy(
        RoleName=exec_name,
        PolicyName="stackset-execution",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["cloudformation:*", "sns:*"], "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=exec_name, PolicyName="stackset-execution"), "NoSuchEntity"
    ))
    iam.put_role_policy(
        RoleName=admin_name,
        PolicyName="assume-execution-role",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": exec_arn}],
            }
        ),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="assume-execution-role"), "NoSuchEntity"
    ))
    return admin_arn, exec_name


def _teardown_stack_set(cfn, ss_name) -> None:
    """Wait out open operations, detach any instance keeping its stack, then delete the stack set."""
    try:
        ops = [op for page in cfn.get_paginator("list_stack_set_operations").paginate(StackSetName=ss_name)
               for op in page["Summaries"]]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    for op in ops:
        if op["Status"] in ("RUNNING", "QUEUED", "STOPPING"):
            _wait_operation(cfn, ss_name, op["OperationId"])
    instances = [i for page in cfn.get_paginator("list_stack_instances").paginate(StackSetName=ss_name)
                 for i in page["Summaries"]]
    if instances:
        op_id = cfn.delete_stack_instances(
            StackSetName=ss_name,
            Accounts=sorted({i["Account"] for i in instances}),
            Regions=sorted({i["Region"] for i in instances}),
            RetainStacks=True,
        )["OperationId"]
        status = _wait_operation(cfn, ss_name, op_id)
        if status != "SUCCEEDED":
            raise AssertionError(f"teardown DeleteStackInstances on {ss_name} ended {status}")
    cfn.delete_stack_set(StackSetName=ss_name)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
