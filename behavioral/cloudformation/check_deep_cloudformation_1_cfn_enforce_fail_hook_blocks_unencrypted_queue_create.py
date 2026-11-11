"""deep-cloudformation-1-cfn-enforce-fail-hook-blocks-unencrypted-queue-create."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-1-cfn-enforce-fail-hook-blocks-unencrypted-queue-create"
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
_HOOK_RESULT_REASON = f"Template failed validation, the following rule(s) failed: {_RULE_NAME}."
_HOOK_EVENT_REASON = f"Hook failed with message: {_HOOK_RESULT_REASON}"


@tags("plane:control", "cap:c3", "concern:negative-classes", "concern:deploy", "axis:rejection")
def run(ctx) -> None:
    """A FAIL-mode STACK Guard hook rolls back CreateStack for an unencrypted SQS queue (never
    created in SQS), lets a compliant twin provision, and reports the verdict in ListHookResults."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    suffix = ctx.unique_name("")  # 12 hex chars, shared by every name in this check
    role_name = f"sim2real-cfnenf-hookrole-{suffix}"
    bucket = f"sim2real-cfnenf-rules-{suffix}"
    hook_stack = f"sim2real-cfnenf-hook-{suffix}"
    good_stack = f"sim2real-cfnenf-good-{suffix}"
    bad_stack = f"sim2real-cfnenf-bad-{suffix}"
    alias = f"Sim2real::Enforce::Fail{suffix}"

    role_arn = _create_hook_role(ctx, iam, role_name, bucket)
    _create_rule_bucket(ctx, s3, bucket)
    hook_arn, hook_stack_id = _deploy_guard_hook(
        ctx, cfn, hook_stack, alias, bucket, role_arn, "FAIL", [good_stack, bad_stack]
    )

    # Positive control: the compliant twin provisions under the same enforcing hook.
    good = _create_stack(ctx, cfn, good_stack, _queue_template(good_stack, sse=True))
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"compliant stack under the FAIL hook ended {good['StackStatus']!r} "
        f"({good.get('StackStatusReason')!r}); the hook must pass an SSE-enabled queue"
    )
    good_url = sqs.get_queue_url(QueueName=good_stack)["QueueUrl"]
    good_sse = sqs.get_queue_attributes(
        QueueUrl=good_url, AttributeNames=["SqsManagedSseEnabled"]
    )["Attributes"].get("SqsManagedSseEnabled")
    assert good_sse == "true", f"compliant queue SqsManagedSseEnabled={good_sse!r}, expected 'true'"

    # The one broken thing: the queue declares SqsManagedSseEnabled=false and no KMS key.
    bad = _create_stack(ctx, cfn, bad_stack, _queue_template(bad_stack, sse=False))
    assert bad["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"non-compliant stack under the FAIL hook ended {bad['StackStatus']!r} "
        f"({bad.get('StackStatusReason')!r}), expected ROLLBACK_COMPLETE"
    )
    events = _all_events(cfn, bad["StackId"])
    hook_events = [e for e in events if e.get("HookStatus") == "HOOK_COMPLETE_FAILED"]
    assert len(hook_events) == 1, (
        f"expected exactly one HOOK_COMPLETE_FAILED stack event, got "
        f"{[(e['LogicalResourceId'], e.get('HookStatus')) for e in events]!r}"
    )
    he = hook_events[0]
    assert he["LogicalResourceId"] == bad_stack, (
        f"hook failure attributed to {he['LogicalResourceId']!r}, expected the stack itself"
    )
    assert he.get("HookType") == alias, f"hook event HookType={he.get('HookType')!r}, expected {alias!r}"
    assert he.get("HookFailureMode") == "FAIL", f"HookFailureMode={he.get('HookFailureMode')!r}"
    assert he.get("HookInvocationPoint") == "PRE_PROVISION", (
        f"HookInvocationPoint={he.get('HookInvocationPoint')!r}, expected PRE_PROVISION"
    )
    assert he.get("HookStatusReason") == _HOOK_EVENT_REASON, (
        f"hook reason {he.get('HookStatusReason')!r}, expected {_HOOK_EVENT_REASON!r}"
    )
    # PRE_PROVISION means the queue was never even attempted.
    queue_events = [e for e in events if e["LogicalResourceId"] == "Q"]
    assert queue_events == [], (
        f"the blocked stack still emitted resource events for the queue: "
        f"{[(e.get('ResourceStatus'), e.get('ResourceStatusReason')) for e in queue_events]!r}"
    )

    # Effect absent, observed at SQS itself.
    code, message = _error(lambda: sqs.get_queue_url(QueueName=bad_stack))
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"GetQueueUrl for the blocked queue returned {code!r}; the queue must not exist"
    )
    assert message == "The specified queue does not exist.", (
        f"GetQueueUrl for the blocked queue returned message {message!r}"
    )

    # The verdict, from ListHookResults keyed by the hook's ARN.
    failed = _hook_results_until(
        cfn, hook_arn, "HOOK_COMPLETE_FAILED",
        lambda rs: any(r.get("HookExecutionTarget") == bad["StackId"] for r in rs),
        timeout=_budget_s(ctx, 120),
        ctx=ctx,
    )
    targets = {r.get("HookExecutionTarget") for r in failed}
    assert targets == {bad["StackId"]}, (
        f"HOOK_COMPLETE_FAILED results target {sorted(t or '' for t in targets)!r}, "
        f"expected only the blocked stack {bad['StackId']!r}"
    )
    fr = failed[0]
    assert fr.get("FailureMode") == "FAIL", f"hook result FailureMode={fr.get('FailureMode')!r}"
    assert fr.get("InvocationPoint") == "PRE_PROVISION", (
        f"hook result InvocationPoint={fr.get('InvocationPoint')!r}"
    )
    assert fr.get("HookStatusReason") == _HOOK_RESULT_REASON, (
        f"hook result reason {fr.get('HookStatusReason')!r}, expected {_HOOK_RESULT_REASON!r}"
    )
    succeeded = _list_hook_results(cfn, hook_arn, "HOOK_COMPLETE_SUCCEEDED")
    assert good["StackId"] in {r.get("HookExecutionTarget") for r in succeeded}, (
        f"no HOOK_COMPLETE_SUCCEEDED result for the compliant stack; succeeded targets were "
        f"{sorted(r.get('HookExecutionTarget') or '' for r in succeeded)!r}"
    )

    # The modelled STACK target type is refused by the service for ListHookResults.
    code, message = _error(
        lambda: cfn.list_hook_results(TargetType="STACK", TargetId=bad["StackId"])
    )
    assert code == "ValidationError", (
        f"ListHookResults(TargetType=STACK) returned {code!r}, expected ValidationError"
    )
    assert message == "Invalid TargetType: STACK", (
        f"ListHookResults(TargetType=STACK) returned message {message!r}"
    )

    _teardown(ctx, cfn, [good["StackId"], bad["StackId"]], hook_stack_id)



class _Succeeded(Exception):
    """Raised by _error when a call expected to fail succeeds."""


def _error(fn) -> tuple[str, str]:
    """Call fn(); return (code, message) of the ClientError raised."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
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
                    # A Guard hook is account-and-region wide; scope it to this check's stacks.
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


def _teardown(ctx, cfn, target_ids: list[str], hook_stack_id: str) -> None:
    """Delete target stacks first (the hook runs on their DELETE and needs its role and rule),
    then the hook stack, while the check's own budget lasts; the cleanups finish the rest."""
    for sid in target_ids:
        cfn.delete_stack(StackName=sid)
    for sid in target_ids + [hook_stack_id]:
        if sid == hook_stack_id:
            cfn.delete_stack(StackName=sid)
        deadline = time.time() + _budget_s(ctx, 600)
        while time.time() < deadline:
            if cfn.describe_stacks(StackName=sid)["Stacks"][0]["StackStatus"] in (
                    "DELETE_COMPLETE", "DELETE_FAILED"):
                break
            time.sleep(1)
        else:
            return


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_stack(ctx, cfn, name: str, body: str) -> dict:
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return _wait_terminal(cfn, stack_id, timeout=_budget_s(ctx, 600), ctx=ctx)


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
        time.sleep(1)
    raise RuntimeError(f"stack {stack_id} did not finish deleting within 600s")


def _wait_terminal(cfn, stack_id: str, timeout: float = 600, ctx=None) -> dict:
    deadline = time.time() + timeout
    while True:
        st = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not st["StackStatus"].endswith("_IN_PROGRESS"):
            return st
        if time.time() >= deadline and ctx is not None and _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_id} leaving _IN_PROGRESS: the run budget ended "
                               "first; not graded")
        assert time.time() < deadline, (
            f"stack {stack_id} still {st['StackStatus']!r} after {timeout:.0f}s"
        )
        time.sleep(1)


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


def _hook_results_until(cfn, hook_arn: str, status: str, cond, timeout: float = 120,
                        ctx=None) -> list[dict]:
    deadline = time.time() + timeout
    while True:
        rs = _list_hook_results(cfn, hook_arn, status)
        if cond(rs):
            return rs
        if time.time() >= deadline and ctx is not None and _budget_spent(ctx):
            raise TimeoutError(f"ListHookResults(TypeArn, Status={status}) showing the expected "
                               "target: the run budget ended first; not graded")
        assert time.time() < deadline, (
            f"ListHookResults(TypeArn, Status={status}) never showed the expected target; "
            f"last saw {[r.get('HookExecutionTarget') for r in rs]!r}"
        )
        time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
