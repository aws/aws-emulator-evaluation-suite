"""deploy-secretsmanager-resourcepolicy-attached-then-removed-by-stack-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-secretsmanager-resourcepolicy-attached-then-removed-by-stack-update"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
_ROOT = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}


def _policy(deny_action: str, root_arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyOneAction",
            "Effect": "Deny",
            "Principal": {"AWS": root_arn},
            "Action": deny_action,
            "Resource": "*",
        }],
    }


def _template(secret_name: str, secret_value: str, deny_action: str, root_arn: str,
              with_policy: bool) -> str:
    resources = {
        "Secret": {
            "Type": "AWS::SecretsManager::Secret",
            "Properties": {"Name": secret_name, "SecretString": secret_value},
        },
    }
    if with_policy:
        resources["SecretPolicy"] = {
            "Type": "AWS::SecretsManager::ResourcePolicy",
            "Properties": {
                "SecretId": {"Ref": "Secret"},
                "BlockPublicPolicy": True,
                "ResourcePolicy": _policy(deny_action, root_arn),
            },
        }
    outputs = {"SecretArn": {"Value": {"Ref": "Secret"}}}
    if with_policy:
        outputs["PolicyRef"] = {"Value": {"Ref": "SecretPolicy"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN ResourcePolicy is attached at SecretsManager with the template's exact statement.
    A stack update dropping the resource removes it there too, leaving the secret untouched, and
    the secret itself is gone only once the whole stack is deleted.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-resourcepolicy.html
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-behav-cfn-smrp-")
    stack_name = ctx.unique_name("sim2real-behav-cfn-smrp-")
    secret_value = ctx.unique_name("sim2real-behav-val-")
    deny_action = "secretsmanager:PutSecretValue"

    stack_id = create_stack(
        ctx, cf, stack_name,
        _template(secret_name, secret_value, deny_action, _ROOT, with_policy=True),
    )
    created = wait_stack(cf, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    root_arn = f"arn:{stack_id.split(':')[1]}:iam::{ctx.account}:root"

    outputs = stack_outputs(cf, stack_id)
    secret_arn = outputs["SecretArn"]

    # ---- Ref is the secret's own identifier, as an independent listing by name shows. ----
    listed = [s for s in paginate(sm, "list_secrets", "SecretList",
                                  Filters=[{"Key": "name", "Values": [secret_name]}])
              if s["Name"] == secret_name]
    assert [s["ARN"] for s in listed] == [secret_arn], (
        f"ListSecrets by name returned {listed!r}, expected the Secret's Ref"
    )
    assert outputs["PolicyRef"] == secret_arn, (
        f"the ResourcePolicy Ref was {outputs['PolicyRef']!r}, expected the secret ARN"
    )
    described = sm.describe_secret(SecretId=secret_arn)
    assert described["Name"] == secret_name, (
        f"expected DescribeSecret Name {secret_name!r}, got {described.get('Name')!r}"
    )
    created_date = described["CreatedDate"]

    # ---- A property the template set reads back through the owning service. ----
    value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert value == secret_value, f"expected SecretString {secret_value!r}, got {value!r}"

    # ---- The ResourcePolicy resource is real at SecretsManager, with the declared statement. ----
    attached = json.loads(sm.get_resource_policy(SecretId=secret_arn)["ResourcePolicy"])
    assert attached == _policy(deny_action, root_arn), (
        f"the attached resource policy read back as {attached!r}"
    )

    # ---- update: drop the ResourcePolicy resource, keeping the secret ----
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(secret_name, secret_value, deny_action, _ROOT, with_policy=False),
    )
    updated = wait_stack(cf, stack_id)
    assert updated == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {updated!r}"

    resources = {
        r["LogicalResourceId"]
        for r in cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    }
    assert "SecretPolicy" not in resources, (
        f"SecretPolicy logical resource still present after the update: {resources!r}"
    )

    # The removal is real at SecretsManager, not merely reported by CFN: GetResourcePolicy still
    # answers for this still-valid SecretId, but carries no ResourcePolicy field.
    after = sm.get_resource_policy(SecretId=secret_arn)
    assert "ResourcePolicy" not in after, (
        f"secret {secret_arn!r} still carries a ResourcePolicy after the resource was removed by "
        f"the stack update: {after!r}"
    )

    # The secret itself is untouched by the update: the same secret, not a replacement.
    after_described = sm.describe_secret(SecretId=secret_arn)
    assert (after_described["ARN"], after_described["CreatedDate"]) == (secret_arn, created_date), (
        f"the secret after the update was ARN {after_described['ARN']!r} created "
        f"{after_described['CreatedDate']!r}, expected the original created {created_date!r}"
    )
    still_there = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert still_there == secret_value, (
        f"expected the secret to be unaffected by the update, got SecretString {still_there!r}"
    )

    # ---- full delete: the secret is only actually gone once the stack itself is torn down ----
    delete_stack(cf, stack_id)
    expect_error(lambda: sm.describe_secret(SecretId=secret_arn), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
