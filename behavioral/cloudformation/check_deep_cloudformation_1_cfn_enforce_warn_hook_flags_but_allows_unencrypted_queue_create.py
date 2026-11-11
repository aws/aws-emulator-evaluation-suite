"""deep-cloudformation-1-cfn-enforce-warn-hook-flags-but-allows-unencrypted-queue-create."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-1-cfn-enforce-warn-hook-flags-but-allows-unencrypted-queue-create"
GROUP = "deploy-guard-hook-enforcement"
SERVICES = ["cloudformation"]

# A Guard rule that denies any AWS::SQS::Queue declaring neither SSE-KMS nor SSE-SQS.
_DENY_GUARD = """let queues = Resources.*[ Type == 'AWS::SQS::Queue' ]

rule sqs_queue_must_be_encrypted when %queues !empty {
    %queues {
        Properties.KmsMasterKeyId exists or
        Properties.SqsManagedSseEnabled == true
    }
}
"""
_RULE_NAME = "sqs_queue_must_be_encrypted"


@tags("plane:control", "cap:c3", "concern:negative-classes", "concern:deploy", "axis:happy-path")
def run(ctx) -> None:
    """A WARN-mode Guard hook records HOOK_COMPLETE_FAILED for an unencrypted SQS queue in stack
    events and ListHookResults, yet the stack reaches CREATE_COMPLETE and the queue exists, SSE off.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    suffix = ctx.unique_name("")
    role_name = f"sim2real-cfnenf-hookrole-{suffix}"
    bucket = f"sim2real-cfnenf-rules-{suffix}"
    hook_stack = f"sim2real-cfnenf-hook-{suffix}"
    warn_stack = f"sim2real-cfnenf-warn-{suffix}"
    alias = f"Sim2real::Enforce::Warn{suffix}"

    role_arn = _create_hook_role(ctx, iam, role_name, bucket)
    _create_rule_bucket(ctx, s3, bucket)
    hook_arn, hook_stack_id = _deploy_guard_hook(
        ctx, cfn, hook_stack, alias, bucket, role_arn, "WARN", [warn_stack]
    )

    st = _create_stack(ctx, cfn, warn_stack, _queue_template(warn_stack, sse=False))
    assert st["StackStatus"] == "CREATE_COMPLETE", (
        f"unencrypted-queue stack under the WARN hook ended {st['StackStatus']!r} "
        f"({st.get('StackStatusReason')!r}); WARN must not block provisioning"
    )

    events = _all_events(cfn, st["StackId"])
    statuses = [e.get("ResourceStatus") for e in events if e["LogicalResourceId"] == warn_stack]
    assert not any("ROLLBACK" in (s or "") for s in statuses), (
        f"the WARN-mode stack entered a rollback: {statuses!r}"
    )
    hook_events = [e for e in events if e.get("HookStatus") == "HOOK_COMPLETE_FAILED"]
    assert len(hook_events) == 1, (
        f"expected exactly one HOOK_COMPLETE_FAILED stack event (the rule still fails under "
        f"WARN), got {[(e['LogicalResourceId'], e.get('HookStatus')) for e in events]!r}"
    )
    he = hook_events[0]
    assert he["LogicalResourceId"] == warn_stack, (
        f"hook failure attributed to {he['LogicalResourceId']!r}, expected the stack itself"
    )
    assert he.get("HookType") == alias, f"hook event HookType={he.get('HookType')!r}"
    assert he.get("HookFailureMode") == "WARN", f"HookFailureMode={he.get('HookFailureMode')!r}"
    assert _RULE_NAME in (he.get("HookStatusReason") or ""), (
        f"hook reason {he.get('HookStatusReason')!r} does not name {_RULE_NAME!r}"
    )
    q_final = [e.get("ResourceStatus") for e in events if e["LogicalResourceId"] == "Q"]
    assert "CREATE_COMPLETE" in q_final, f"queue resource events {q_final!r} show no CREATE_COMPLETE"

    # The flagged queue really exists, unencrypted, at SQS itself.
    url = sqs.get_queue_url(QueueName=warn_stack)["QueueUrl"]
    sse = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["SqsManagedSseEnabled", "KmsMasterKeyId"]
    )["Attributes"]
    assert sse.get("SqsManagedSseEnabled") == "false", f"queue SSE attributes {sse!r}, expected SSE off"
    assert "KmsMasterKeyId" not in sse, f"queue unexpectedly carries a KMS key: {sse!r}"

    failed = _hook_results_until(
        cfn, hook_arn, "HOOK_COMPLETE_FAILED",
        lambda rs: any(r.get("HookExecutionTarget") == st["StackId"] for r in rs),
    )
    mine = [r for r in failed if r.get("HookExecutionTarget") == st["StackId"]]
    assert len(mine) == 1, f"expected one failed hook result for the stack, got {mine!r}"
    assert mine[0].get("FailureMode") == "WARN", (
        f"hook result FailureMode={mine[0].get('FailureMode')!r}, expected WARN"
    )
    assert _RULE_NAME in (mine[0].get("HookStatusReason") or ""), (
        f"hook result reason {mine[0].get('HookStatusReason')!r} does not name {_RULE_NAME!r}"
    )

    _teardown(cfn, [st["StackId"]], hook_stack_id)



class _Succeeded(Exception):
    """Raised by _error_code when a call expected to fail succeeds."""


def _error_code(fn) -> str:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise _Succeeded("call expected to fail succeeded")


def _queue_template(queue_name: str, *, sse: bool) -> str:
    return json.dumps({
        "Resources": {
            "Q": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_name, "SqsManagedSseEnabled": sse},
            }
        }
    })


def _create_hook_role(ctx, iam, role_name: str, bucket: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": ["hooks.cloudformation.amazonaws.com",
                                      "resources.cloudformation.amazonaws.com"]},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real cfn guard hook execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _drop_role() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="read-guard-rules")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_drop_role)
    iam.put_role_policy(
        RoleName=role_name, PolicyName="read-guard-rules",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    return arn


def _create_rule_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _drop_bucket() -> None:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_drop_bucket)
    s3.put_object(Bucket=bucket, Key="deny.guard", Body=_DENY_GUARD.encode())


def _deploy_guard_hook(ctx, cfn, stack: str, alias: str, bucket: str, role_arn: str,
                       mode: str, include: list[str]) -> tuple[str, str]:
    template = {
        "Resources": {
            "Hook": {
                "Type": "AWS::CloudFormation::GuardHook",
                "Properties": {
                    "Alias": alias,
                    "RuleLocation": {"Uri": f"s3://{bucket}/deny.guard"},
                    "ExecutionRole": role_arn,
                    "TargetOperations": ["STACK"],
                    "HookStatus": "ENABLED",
                    "FailureMode": mode,
                    # A Guard hook is account-and-region wide; scope it to this check's stack.
                    "StackFilters": {
                        "FilteringCriteria": "ALL",
                        "StackNames": {"Include": include},
                    },
                },
            }
        },
        "Outputs": {"HookArn": {"Value": {"Fn::GetAtt": ["Hook", "HookArn"]}}},
    }
    st = _create_stack(ctx, cfn, stack, json.dumps(template))
    assert st["StackStatus"] == "CREATE_COMPLETE", (
        f"guard hook stack ended {st['StackStatus']!r} ({st.get('StackStatusReason')!r})"
    )
    outs = {o["OutputKey"]: o["OutputValue"] for o in st.get("Outputs", [])}
    assert outs.get("HookArn", "").startswith("arn:"), f"hook stack outputs {outs!r} carry no HookArn"
    return outs["HookArn"], st["StackId"]


def _teardown(cfn, target_ids: list[str], hook_stack_id: str) -> None:
    """Delete target stacks first (the hook runs on their DELETE and needs its role and rule),
    then the hook stack, inside the check's own budget rather than the 60 s cleanup bound."""
    for sid in target_ids:
        cfn.delete_stack(StackName=sid)
    for sid in target_ids + [hook_stack_id]:
        if sid == hook_stack_id:
            cfn.delete_stack(StackName=sid)
        deadline = time.time() + 600
        while time.time() < deadline:
            if cfn.describe_stacks(StackName=sid)["Stacks"][0]["StackStatus"] in (
                    "DELETE_COMPLETE", "DELETE_FAILED"):
                break
            time.sleep(5)


def _create_stack(ctx, cfn, name: str, body: str) -> dict:
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return _wait_terminal(cfn, stack_id)


def _delete_stack(cfn, stack_id: str) -> None:
    if cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
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


def _list_hook_results(cfn, hook_arn: str, status: str) -> list[dict]:
    out: list[dict] = []
    kwargs = {"TypeArn": hook_arn, "Status": status}
    while True:
        resp = cfn.list_hook_results(**kwargs)
        out.extend(resp.get("HookResults", []))
        if not resp.get("NextToken"):
            return out
        kwargs["NextToken"] = resp["NextToken"]


def _hook_results_until(cfn, hook_arn: str, status: str, cond, timeout: float = 120) -> list[dict]:
    deadline = time.time() + timeout
    while True:
        rs = _list_hook_results(cfn, hook_arn, status)
        if cond(rs):
            return rs
        assert time.time() < deadline, (
            f"ListHookResults(TypeArn, Status={status}) never showed the expected target; "
            f"last saw {[r.get('HookExecutionTarget') for r in rs]!r}"
        )
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
