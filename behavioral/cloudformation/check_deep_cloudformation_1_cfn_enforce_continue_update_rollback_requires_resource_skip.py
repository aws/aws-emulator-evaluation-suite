"""deep-cloudformation-1-cfn-enforce-continue-update-rollback-requires-resource-skip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-1-cfn-enforce-continue-update-rollback-requires-resource-skip"
GROUP = "deploy-stack-recovery"
SERVICES = ["cloudformation"]


# timing:real-time — workflow: 90 s https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-waitcondition.html
@tags("plane:control", "cap:c3", "concern:negative-classes", "concern:deploy", "axis:rejection", "timing:real-time")
def run(ctx) -> None:
    """From UPDATE_ROLLBACK_FAILED, ContinueUpdateRollback without ResourcesToSkip falls back to
    UPDATE_ROLLBACK_FAILED; skipping the stuck queue reaches UPDATE_ROLLBACK_COMPLETE and leaves
    the queue with its updated VisibilityTimeout."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    suffix = ctx.unique_name("")
    role_name = f"sim2real-cfnenf-svcrole-{suffix}"
    stack = f"sim2real-cfnenf-cur-{suffix}"
    queue_arn = f"arn:aws:sqs:{ctx.region}:{account}:{stack}"

    role_arn = _create_service_role(ctx, iam, role_name, queue_arn)

    v1 = _template(stack, visibility=30, with_wait=False)
    stack_id = _create_stack_as_role(ctx, cfn, stack, v1, role_arn)
    st = _wait_terminal(cfn, stack_id)
    assert st["StackStatus"] == "CREATE_COMPLETE", (
        f"v1 ended {st['StackStatus']!r} ({st.get('StackStatusReason')!r})"
    )
    url = sqs.get_queue_url(QueueName=stack)["QueueUrl"]
    assert _visibility(sqs, url) == "30", f"v1 queue VisibilityTimeout={_visibility(sqs, url)!r}"

    n_before = len(_all_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, visibility=60, with_wait=True),
                     RoleARN=role_arn)
    _wait_queue_updated(cfn, stack_id, n_before)

    # Deny on the service role, not a Guard hook: a STACK-target hook is not invoked on rollback.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="deny-set-attributes",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "sqs:SetQueueAttributes", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda: _drop_policy(iam, role_name, "deny-set-attributes"))

    st = _wait_terminal(cfn, stack_id, timeout=900)
    assert st["StackStatus"] == "UPDATE_ROLLBACK_FAILED", (
        f"after the denied rollback the stack is {st['StackStatus']!r} "
        f"({st.get('StackStatusReason')!r}), expected UPDATE_ROLLBACK_FAILED"
    )
    assert _visibility(sqs, url) == "60", (
        f"queue VisibilityTimeout={_visibility(sqs, url)!r}; the denied rollback must leave it at 60"
    )
    assert _resource_status(cfn, stack_id, "Q") == "UPDATE_FAILED", (
        f"queue resource status {_resource_status(cfn, stack_id, 'Q')!r}, expected UPDATE_FAILED"
    )

    # Recovery WITHOUT skip info: accepted, but the stack falls back into the failed state.
    cfn.continue_update_rollback(StackName=stack_id, RoleARN=role_arn)
    st = _wait_terminal(cfn, stack_id, timeout=900)
    assert st["StackStatus"] == "UPDATE_ROLLBACK_FAILED", (
        f"ContinueUpdateRollback without ResourcesToSkip reached {st['StackStatus']!r}; with the "
        f"deny still in place it must re-enter UPDATE_ROLLBACK_FAILED"
    )
    assert _visibility(sqs, url) == "60", (
        f"queue VisibilityTimeout={_visibility(sqs, url)!r} after the refused continue"
    )

    # Recovery WITH the stuck resource skipped converges.
    cfn.continue_update_rollback(StackName=stack_id, RoleARN=role_arn, ResourcesToSkip=["Q"])
    st = _wait_terminal(cfn, stack_id, timeout=900)
    assert st["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"ContinueUpdateRollback with ResourcesToSkip=['Q'] reached {st['StackStatus']!r} "
        f"({st.get('StackStatusReason')!r}), expected UPDATE_ROLLBACK_COMPLETE"
    )
    assert _visibility(sqs, url) == "60", (
        f"skipped queue VisibilityTimeout={_visibility(sqs, url)!r}; a skipped resource must be "
        f"left as the failed update made it, not reverted to 30"
    )
    resources = {r["LogicalResourceId"] for r in cfn.describe_stack_resources(
        StackName=stack_id)["StackResources"]}
    assert resources == {"Q"}, f"after rollback the stack holds {sorted(resources)!r}, expected only Q"

    # Success-path teardown inside the check's own budget; cleanups are bounded at 60 s.
    _drop_policy(iam, role_name, "deny-set-attributes")
    _delete_stack(cfn, stack_id, role_arn)



def _template(queue_name: str, *, visibility: int, with_wait: bool) -> str:
    res: dict = {
        "Q": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"QueueName": queue_name, "VisibilityTimeout": visibility,
                           "SqsManagedSseEnabled": True},
        }
    }
    if with_wait:
        # Never signalled: times out, failing the update after Q has already been updated.
        res["H"] = {"Type": "AWS::CloudFormation::WaitConditionHandle"}
        res["W"] = {
            "Type": "AWS::CloudFormation::WaitCondition",
            "DependsOn": "Q",
            "Properties": {"Handle": {"Ref": "H"}, "Timeout": "90", "Count": 1},
        }
    return json.dumps({"Resources": res})


def _create_service_role(ctx, iam, role_name: str, queue_arn: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real cfn stack service role", Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _drop_role() -> None:
        for name in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            _drop_policy(iam, role_name, name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_drop_role)
    iam.put_role_policy(
        RoleName=role_name, PolicyName="manage-queue",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:*", "Resource": queue_arn},
                          {"Effect": "Allow", "Action": "sqs:ListQueues", "Resource": "*"}],
        }),
    )
    return arn


def _create_stack_as_role(ctx, cfn, name: str, body: str, role_arn: str) -> str:
    # First use of the new role: CreateStack refuses a role IAM has not propagated yet.
    deadline = time.time() + 90
    while True:
        try:
            stack_id = cfn.create_stack(StackName=name, TemplateBody=body, RoleARN=role_arn,
                                        Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
            ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id, role_arn))
            break
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if exc.response["Error"]["Code"] == "ValidationError" and "role" in msg.lower() \
                    and time.time() < deadline:
                time.sleep(5)
                continue
            raise
    return stack_id


def _drop_policy(iam, role_name: str, policy: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_stack(cfn, stack_id: str, role_arn: str) -> None:
    if cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id, RoleARN=role_arn)
    deadline = time.time() + 600
    while time.time() < deadline:
        st = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if st == "DELETE_COMPLETE":
            return
        if st == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_id} DELETE_FAILED")
        time.sleep(5)
    raise RuntimeError(f"stack {stack_id} did not finish deleting within 600s")


def _wait_terminal(cfn, stack_id: str, timeout: float = 600) -> dict:
    deadline = time.time() + timeout
    while True:
        st = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not st["StackStatus"].endswith("_IN_PROGRESS"):
            return st
        assert time.time() < deadline, (
            f"stack {stack_id} still {st['StackStatus']!r} after {timeout:.0f}s"
        )
        time.sleep(5)


def _all_events(cfn, stack_id: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out


def _wait_queue_updated(cfn, stack_id: str, n_before: int, timeout: float = 300) -> None:
    deadline = time.time() + timeout
    while True:
        events = _all_events(cfn, stack_id)
        new = events[: len(events) - n_before]  # newest first
        if any(e["LogicalResourceId"] == "Q" and e.get("ResourceStatus") == "UPDATE_COMPLETE"
               for e in new):
            return
        assert time.time() < deadline, (
            f"queue never reached UPDATE_COMPLETE during the update; new events "
            f"{[(e['LogicalResourceId'], e.get('ResourceStatus')) for e in new]!r}"
        )
        time.sleep(3)


def _visibility(sqs, url: str) -> str | None:
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"]
    )["Attributes"].get("VisibilityTimeout")


def _resource_status(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["ResourceStatus"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
