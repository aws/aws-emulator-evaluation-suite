"""cfn-stackset-instance-deployed-queue-is-functional-and-tracks-updates."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stackset-instance-deployed-queue-is-functional-and-tracks-updates"

GROUP = "deploy_stacksets"

SERVICES = ["cloudformation", "sqs"]

_OP_TERMINAL = {"SUCCEEDED", "FAILED", "STOPPED"}
# Upper bound for freshly created IAM roles to become usable by StackSets.
_IAM_PROPAGATION_S = 300.0


def _template(queue_name: str, visibility_timeout: int) -> str:
    return json.dumps({
        "Resources": {
            "Queue": {"Type": "AWS::SQS::Queue",
                      "Properties": {"QueueName": queue_name,
                                     "VisibilityTimeout": visibility_timeout}},
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "Queue"}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack set instance deploys a queue that round-trips a message, and after UpdateStackSet
    reports SUCCEEDED the live queue already carries the new VisibilityTimeout, unreplaced.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    queue_name = _xname(ctx, "ss-q")
    ctx.on_cleanup(lambda: _delete_queue_by_name_if_present(sqs, queue_name))

    # Self-managed stack sets need an administration/execution role pair. The AWS default role
    # names are fixed, so a uniquely named pair is created and passed to CreateStackSet.
    exec_role, admin_arn = _stackset_roles(ctx, account)

    stack_set = _xname(ctx, "ss")
    cfn.create_stack_set(
        StackSetName=stack_set, TemplateBody=_template(queue_name, 30),
        PermissionModel="SELF_MANAGED", AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Tags=_tags_kv())
    ctx.on_cleanup(lambda: _delete_stack_set_if_present(cfn, stack_set))

    op_id = _create_instances_with_iam_retry(ctx, stack_set, account, region)
    ctx.on_cleanup(lambda: _delete_instances(ctx, stack_set, account, region))
    op = _await_operation(cfn, stack_set, op_id, timeout_s=900.0)
    assert op["Status"] == "SUCCEEDED", (
        f"instance creation did not succeed: {op!r}; results were "
        f"{_operation_results(cfn, stack_set, op_id)!r}"
    )

    instances = _stack_instances(cfn, stack_set)
    assert len(instances) == 1, f"expected exactly one instance, got {instances!r}"
    instance = instances[0]
    assert instance["Status"] == "CURRENT", (
        f"the instance must be CURRENT after a SUCCEEDED create: {instance!r}"
    )

    instance_stack = instance["StackId"]
    queue_url = _physical_id(cfn, instance_stack, "Queue")
    assert queue_url, (
        f"the stack set instance reported no queue; instance was {instance!r}"
    )

    marker = f"stackset-instance-{queue_name}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=marker)
    received = _receive_one(sqs, queue_url, timeout_s=180.0)
    assert received["Body"] == marker, (
        f"the stack-set-deployed queue is not functional: {received!r}"
    )
    assert _visibility_timeout(sqs, queue_url) == "30", (
        f"the deployed queue does not carry the template's property: "
        f"{_visibility_timeout(sqs, queue_url)!r}"
    )

    update_op = cfn.update_stack_set(
        StackSetName=stack_set, TemplateBody=_template(queue_name, 45),
        PermissionModel="SELF_MANAGED", AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_role,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        OperationPreferences={"FailureToleranceCount": 0, "MaxConcurrentCount": 1},
    )["OperationId"]
    done = _await_operation(cfn, stack_set, update_op, timeout_s=900.0)
    assert done["Status"] == "SUCCEEDED", (
        f"the stack set update did not succeed: {done!r}; results were "
        f"{_operation_results(cfn, stack_set, update_op)!r}"
    )

    # Read once, not polled: SUCCEEDED must mean the target has already converged.
    converged = _visibility_timeout(sqs, queue_url)
    assert converged == "45", (
        f"the operation reported SUCCEEDED but the target resource did not converge: the live "
        f"queue reports VisibilityTimeout {converged!r}, expected '45'"
    )
    assert _physical_id(cfn, instance_stack, "Queue") == queue_url, (
        f"a VisibilityTimeout change must not replace the deployed queue: {queue_url!r} -> "
        f"{_physical_id(cfn, instance_stack, 'Queue')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_NO_SUCH_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _queue_url_or_none(sqs, name: str) -> str | None:
    try:
        return sqs.get_queue_url(QueueName=name)["QueueUrl"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == _NO_SUCH_QUEUE:
            return None
        raise


def _delete_queue_by_name_if_present(sqs, name: str) -> None:
    """Best-effort queue teardown by name; already-deleted is not an error."""
    url = _queue_url_or_none(sqs, name)
    if url:
        sqs.delete_queue(QueueUrl=url)


def _visibility_timeout(sqs, url: str) -> str:
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]


def _receive_one(sqs, url: str, *, timeout_s=120.0) -> dict[str, Any]:
    """Long-poll a queue until one message arrives; return it (raises on timeout)."""
    msgs = _poll_until(
        lambda: sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1,
                                    WaitTimeSeconds=20).get("Messages", []),
        bool, timeout_s=timeout_s, interval_s=1.0, description=f"a message on {url}")
    return msgs[0]


def _physical_id(cfn, stack: str, logical_id: str) -> str:
    """The PhysicalResourceId CloudFormation currently records for a logical id."""
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id)["StackResourceDetail"]["PhysicalResourceId"]


def _stackset_roles(ctx, account: str) -> tuple[str, str]:
    """Create the self-managed administration/execution role pair. -> (exec role name, admin arn)."""
    iam = ctx.client("iam")
    exec_name = _xname(ctx, "ssexec")
    admin_name = _xname(ctx, "ssadmin")

    exec_arn = iam.create_role(
        RoleName=exec_name, Path="/",
        Description="sim2real self-managed stack set execution role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}]}),
        Tags=_tags_kv())["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, exec_name))
    iam.put_role_policy(RoleName=exec_name, PolicyName="deploy",
                        PolicyDocument=json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow",
                                           "Action": ["cloudformation:*", "sqs:*"],
                                           "Resource": "*"}]}))

    admin_arn = iam.create_role(
        RoleName=admin_name, Path="/",
        Description="sim2real self-managed stack set administration role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "cloudformation.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}),
        Tags=_tags_kv())["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, admin_name))
    iam.put_role_policy(RoleName=admin_name, PolicyName="assume-exec",
                        PolicyDocument=json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                           "Resource": exec_arn}]}))
    return exec_name, admin_arn


def _delete_role(iam, name: str) -> None:
    """Drop every inline policy, then the role; an already-gone role is not an error."""
    try:
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=name):
            for policy in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=name, PolicyName=policy)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise RuntimeError(f"iam role {name} teardown failed: {exc}") from exc


def _create_instances_with_iam_retry(ctx, stack_set: str, account: str, region: str) -> str:
    """CreateStackInstances, retried while the freshly-created roles are still propagating.

    IAM exposes no condition that says a role is usable, so the retry sits at the role's first use.
    """
    cfn = ctx.client("cloudformation")
    last = None
    # Retries stop once the roles have had _IAM_PROPAGATION_S to become usable.
    deadline = time.monotonic() + _IAM_PROPAGATION_S
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            op_id = cfn.create_stack_instances(
                StackSetName=stack_set, Accounts=[account], Regions=[region],
                OperationPreferences={"FailureToleranceCount": 0, "MaxConcurrentCount": 1},
            )["OperationId"]
        except ClientError as exc:
            last = exc
        else:
            op = _await_operation(cfn, stack_set, op_id, timeout_s=900.0)
            if op["Status"] == "SUCCEEDED":
                return op_id
            results = _operation_results(cfn, stack_set, op_id)
            last = f"{op!r} {results!r}"
            blob = json.dumps(results, default=str)
            # StackSets reports a not-yet-visible role as missing its CloudFormation trust relationship.
            if not any(m in blob for m in ("AccessDenied", "not authorized", "AssumeRole", "trust relationship")):
                return op_id  # a real failure: let the caller's assertion report it
            # otherwise the roles were not yet usable; drop the failed instance and retry
            _delete_instances(ctx, stack_set, account, region)
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    raise AssertionError(
        f"CreateStackInstances never succeeded within {_IAM_PROPAGATION_S:.0f}s; last was {last!r}")


def _await_operation(cfn, stack_set: str, op_id: str, *, timeout_s=900.0) -> dict[str, Any]:
    return _poll_until(
        lambda: cfn.describe_stack_set_operation(
            StackSetName=stack_set, OperationId=op_id)["StackSetOperation"],
        lambda o: o["Status"] in _OP_TERMINAL, timeout_s=timeout_s, interval_s=10.0,
        description=f"stack set operation {op_id} on {stack_set}")


def _operation_results(cfn, stack_set: str, op_id: str) -> list[dict[str, Any]]:
    """Every per-target result for an operation, paginated -- this is where the reason lives."""
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackSetName": stack_set, "OperationId": op_id}
        if token:
            kwargs["NextToken"] = token
        try:
            page = cfn.list_stack_set_operation_results(**kwargs)
        except ClientError:
            return out
        out.extend(page.get("Summaries", []))
        token = page.get("NextToken")
        if not token:
            return out


def _stack_instances(cfn, stack_set: str) -> list[dict[str, Any]]:
    """Every instance of a stack set, paginated."""
    out: list[dict[str, Any]] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"StackSetName": stack_set}
        if token:
            kwargs["NextToken"] = token
        page = cfn.list_stack_instances(**kwargs)
        out.extend(page.get("Summaries", []))
        token = page.get("NextToken")
        if not token:
            return out


def _delete_instances(ctx, stack_set: str, account: str, region: str) -> None:
    """Delete the instances (not retaining their stacks) and wait until none is listed."""
    cfn = ctx.client("cloudformation")
    try:
        if not _stack_instances(cfn, stack_set):
            return
        op_id = cfn.delete_stack_instances(
            StackSetName=stack_set, Accounts=[account], Regions=[region], RetainStacks=False,
            OperationPreferences={"FailureToleranceCount": 0, "MaxConcurrentCount": 1},
        )["OperationId"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "StackSetNotFoundException":
            return
        raise
    op = _await_operation(cfn, stack_set, op_id, timeout_s=900.0)
    if op["Status"] != "SUCCEEDED":
        raise RuntimeError(f"delete_stack_instances on {stack_set} ended {op['Status']}: "
                           f"{_operation_results(cfn, stack_set, op_id)!r}")
    _poll_until(lambda: _stack_instances(cfn, stack_set), lambda i: not i,
                timeout_s=600.0, interval_s=2.0,
                description=f"instances of {stack_set} gone")


def _delete_stack_set_if_present(cfn, stack_set: str) -> None:
    """Delete the stack set; an already-gone stack set is not an error."""
    try:
        cfn.delete_stack_set(StackSetName=stack_set)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "StackSetNotFoundException":
            raise RuntimeError(f"stack set {stack_set} teardown failed: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
