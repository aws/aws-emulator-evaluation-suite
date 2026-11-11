"""execute-changeset-missing-capabilities-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-changeset-missing-capabilities-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Executing a change set whose nested stack needs CAPABILITY_NAMED_IAM, without it, rolls back.

    CreateChangeSet does not expand the nested template; the nested resource fails asynchronously.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = _create_scratch_bucket(ctx, s3)

    # Positive control: the same pattern with the capability acknowledged reaches CREATE_COMPLETE.
    control_role_name = ctx.unique_name("sim2real-behav-capsxc-ctrl-role-")
    control_nested_key = ctx.unique_name("sim2real-behav-capsxc-ctrl-nested-") + ".json"
    control_template_url = _put_nested_template(ctx, s3, bucket, control_nested_key, control_role_name)
    control_stack = ctx.unique_name("sim2real-behav-capsxc-ctrl-")
    control_cs_name = ctx.unique_name("sim2real-behav-cs-ctrl-")
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, control_stack))
    ctx.on_cleanup(lambda: _safe_delete_role(iam, control_role_name))

    cfn.create_change_set(
        StackName=control_stack, ChangeSetName=control_cs_name,
        TemplateBody=_parent_template(control_template_url), ChangeSetType="CREATE",
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    control_cs_status = _wait_change_set_status(cfn, control_stack, control_cs_name, timeout_s=120)
    assert control_cs_status == "CREATE_COMPLETE", (
        f"positive control: expected CreateChangeSet for the same nested-stack pattern to "
        f"succeed once CAPABILITY_NAMED_IAM is acknowledged, got {control_cs_status}"
    )

    cfn.execute_change_set(ChangeSetName=control_cs_name, StackName=control_stack)
    control_final_status = _wait_stack_terminal_after_execute(cfn, control_stack, timeout_s=300)
    assert control_final_status == "CREATE_COMPLETE", (
        f"positive control: expected the nested stack (and its IAM role) to actually be created "
        f"once CAPABILITY_NAMED_IAM is acknowledged, got {control_final_status} -- without this "
        f"the negative below can't be told apart from a wiring that can never create a nested "
        f"IAM-role stack for reasons unrelated to the missing capability"
    )

    control_role = iam.get_role(RoleName=control_role_name)["Role"]
    assert control_role["RoleName"] == control_role_name, (
        f"positive control: expected the nested stack's IAM role to actually exist once the "
        f"capability was acknowledged, got {control_role!r}"
    )

    # ---- negative: the same pattern, capability omitted -----------------
    role_name = ctx.unique_name("sim2real-behav-capsxc-role-")
    nested_key = ctx.unique_name("sim2real-behav-capsxc-nested-") + ".json"
    template_url = _put_nested_template(ctx, s3, bucket, nested_key, role_name)

    target_stack = ctx.unique_name("sim2real-behav-capsxc-")
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, target_stack))
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))

    # Capabilities omitted: with IncludeNestedStacks False the nested template is not fetched,
    # so CreateChangeSet never sees the IAM role.
    change_set_name = ctx.unique_name("sim2real-behav-cs-")
    cfn.create_change_set(
        StackName=target_stack, ChangeSetName=change_set_name,
        TemplateBody=_parent_template(template_url), ChangeSetType="CREATE",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    status = _wait_change_set_status(cfn, target_stack, change_set_name, timeout_s=120)
    assert status == "CREATE_COMPLETE", (
        f"expected the change set's diff to compute successfully without CAPABILITY_NAMED_IAM "
        f"(the nested stack's IAM role is only discovered at ExecuteChangeSet time), got {status}"
    )

    cfn.execute_change_set(ChangeSetName=change_set_name, StackName=target_stack)

    # ExecuteChangeSet does not reject synchronously; the missing capability surfaces later as
    # the nested resource's CREATE_FAILED, rolling the first-ever stack back to ROLLBACK_COMPLETE.

    final_status = _wait_stack_terminal_after_execute(cfn, target_stack, timeout_s=300)
    assert final_status == "ROLLBACK_COMPLETE", (
        f"expected the target stack to roll back to ROLLBACK_COMPLETE once the nested stack's "
        f"missing-capability failure was discovered, got {final_status}"
    )

    nested_reason = _nested_failure_reason(cfn, target_stack)
    assert nested_reason == "Requires capabilities : [CAPABILITY_NAMED_IAM]", (
        f"expected the nested stack resource's failure reason to cite the missing "
        f"CAPABILITY_NAMED_IAM capability, got {nested_reason!r}"
    )

    resources = cfn.list_stack_resources(StackName=target_stack)["StackResourceSummaries"]
    created = [r for r in resources if r["ResourceStatus"] == "CREATE_COMPLETE"]
    assert not created, f"expected no resources to be created, found {created}"

    role_code, role_msg = _client_error(
        lambda: iam.get_role(RoleName=role_name),
        f"GetRole of the never-created nested IAM role {role_name}",
    )
    assert role_code == "NoSuchEntity", (role_code, role_msg)
    assert role_msg == f"The role with name {role_name} cannot be found.", role_msg


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as e:
        error = e.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_scratch_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-behav-nested-tmpl-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=bucket)))
    return bucket


def _nested_role_template(role_name):
    return json.dumps({
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                },
            },
        },
    })


def _put_nested_template(ctx, s3, bucket, key, role_name):
    nested_template = _nested_role_template(role_name)
    s3.put_object(Bucket=bucket, Key=key, Body=nested_template.encode("utf-8"))
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_object(Bucket=bucket, Key=key)))
    return ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}", bucket, key)


def _parent_template(template_url):
    return json.dumps({
        "Resources": {
            "Nested": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {"TemplateURL": template_url},
            },
        },
    })


def _wait_change_set_status(cfn, stack_name, change_set_name, timeout_s=120, interval_s=3):
    terminal_statuses = {"CREATE_COMPLETE", "FAILED", "DELETE_COMPLETE", "DELETE_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        status = desc["Status"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"change set {change_set_name} never reached a terminal status, last={status}")


def _wait_stack_terminal_after_execute(cfn, stack_name, timeout_s=300, interval_s=5):
    terminal_statuses = {
        "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    }
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached a terminal status after ExecuteChangeSet, last={status}")


def _nested_failure_reason(cfn, stack_name):
    """Return the parent stack's CREATE_FAILED reason for the "Nested" resource."""
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for event in events:
        if event.get("LogicalResourceId") == "Nested" and event.get("ResourceStatus") == "CREATE_FAILED":
            return event.get("ResourceStatusReason", "")
    return ""


def _cleanup_stack(cfn, stack_name):
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 150
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return
            raise
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        status = stacks[0]["StackStatus"]
        if status == "DELETE_FAILED":
            break
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} was not deleted within 150 s (last status {status!r})")


def _safe_delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
