"""deploy-cloudformation-2-lambdahook-rejects-deny-queue."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-2-lambdahook-rejects-deny-queue"

GROUP = "deploy-cfn-lambdahook"

SERVICES = ["cloudformation", "lambda", "sqs"]

_HOOK_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  HookAlias:
    Type: String
  IncludeStacks:
    Type: CommaDelimitedList
Resources:
  CounterQueue:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 3600
  FnRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      # Deliberately NO CloudWatch Logs permissions: the function can never create
      # /aws/lambda/<fn>, so the check cannot leak a log group. The invocation counter
      # is the SQS queue below, not the logs.
      Policies:
        - PolicyName: counter
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sqs:SendMessage
                Resource: !GetAtt CounterQueue.Arn
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 30
      Role: !GetAtt FnRole.Arn
      Environment:
        Variables:
          COUNTER_URL: !Ref CounterQueue
      Code:
        ZipFile: |
          import json, os
          import boto3
          sqs = boto3.client("sqs")
          def handler(event, context):
              rd = event.get("requestData") or {}
              props = (rd.get("targetModel") or {}).get("resourceProperties") or {}
              name = str(props.get("QueueName", ""))
              verdict = "FAILED" if name.startswith("deny-") else "SUCCESS"
              sqs.send_message(QueueUrl=os.environ["COUNTER_URL"], MessageBody=json.dumps({
                  "requestId": context.aws_request_id,
                  "stackId": event.get("stackId"),
                  "logicalId": rd.get("targetLogicalId"),
                  "targetName": rd.get("targetName"),
                  "queueName": name,
                  "invocationPoint": event.get("actionInvocationPoint"),
                  "verdict": verdict,
              }))
              out = {"hookStatus": verdict, "clientRequestToken": event.get("clientRequestToken")}
              if verdict == "FAILED":
                  out["errorCode"] = "NonCompliant"
                  out["message"] = "sim2real: queue names starting with deny- are refused"
              else:
                  out["message"] = "sim2real: queue name allowed"
              return out
  HookRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {Service: hooks.cloudformation.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: invoke
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: lambda:InvokeFunction
                Resource: !GetAtt Fn.Arn
  Hook:
    Type: AWS::CloudFormation::LambdaHook
    Properties:
      Alias: !Ref HookAlias
      LambdaFunction: !GetAtt Fn.Arn
      ExecutionRole: !GetAtt HookRole.Arn
      FailureMode: FAIL
      HookStatus: ENABLED
      TargetOperations: [RESOURCE]
      TargetFilters:
        Actions: [CREATE]
        InvocationPoints: [PRE_PROVISION]
        TargetNames: [AWS::SQS::Queue]
      # Scoped to this check's own stack names, so the hook can never fire on (or
      # be counted against) a sibling run's stacks in the same account.
      StackFilters:
        FilteringCriteria: ALL
        StackNames:
          Include: !Ref IncludeStacks
Outputs:
  CounterQueueUrl:
    Value: !Ref CounterQueue
  HookArn:
    Value: !GetAtt Hook.HookArn
"""

_QUEUE_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  QueueName:
    Type: String
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Ref QueueName
      MessageRetentionPeriod: 3600
Outputs:
  QueueUrl:
    Value: !Ref Queue
"""

_NON_EXISTENT_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FAIL-mode Lambda hook on AWS::SQS::Queue vetoes the deny- stack and never creates its
    queue, allows the allow- twin, runs once per create, and stops vetoing once repaired.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")

    token = uuid.uuid4().hex[:12]
    alias = f"Simreal::Sqs::Lh{token}"
    allow_stack = _xname(ctx, "lh-allow-stk")
    deny_stack = _xname(ctx, "lh-deny-stk")
    allow_queue = f"allow-sim2real-xsvc-lh-{token}-a"
    deny_suffix = f"sim2real-xsvc-lh-{token}-d"
    deny_queue = f"deny-{deny_suffix}"
    restored_queue = f"allow-{deny_suffix}"

    # ---- the hook estate ----
    hook_stack = _xname(ctx, "lh-hook-stk")
    hook_stack_id = _create_stack(
        ctx, hook_stack, _HOOK_TEMPLATE,
        {"HookAlias": alias, "IncludeStacks": f"{allow_stack},{deny_stack}"},
    )
    status = _wait_stack_terminal(ctx, hook_stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"hook stack {hook_stack} ended in {status!r}: {_failure_reasons(ctx, hook_stack_id)!r}"
    )
    hook_out = _outputs(ctx, hook_stack_id)
    counter_url = hook_out["CounterQueueUrl"]
    account = hook_stack_id.split(":")[4]
    want_arn = f"arn:aws:cloudformation:{ctx.region}:{account}:type/hook/{alias.replace('::', '-')}"
    assert hook_out["HookArn"] == want_arn, (
        f"HookArn output {hook_out['HookArn']!r}, expected {want_arn!r}"
    )
    records: dict[str, dict[str, Any]] = {}

    # ---- positive control: an allow- queue passes the hook and works ----
    allow_id = _create_stack(ctx, allow_stack, _QUEUE_TEMPLATE, {"QueueName": allow_queue})
    status = _wait_stack_terminal(ctx, allow_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"allow- stack ended in {status!r}, expected CREATE_COMPLETE (the hook must pass a "
        f"non-deny queue): {_failure_reasons(ctx, allow_id)!r}"
    )
    allow_url = sqs.get_queue_url(QueueName=allow_queue)["QueueUrl"]
    assert allow_url == _outputs(ctx, allow_id)["QueueUrl"], (
        f"SQS resolves {allow_queue!r} to {allow_url!r}, stack output says "
        f"{_outputs(ctx, allow_id)['QueueUrl']!r}"
    )
    _round_trip(sqs, allow_url)
    allow_hook = [(e.get("HookStatus"), e.get("HookStatusReason"))
                  for e in _stack_events(ctx, allow_id)
                  if e["LogicalResourceId"] == "Queue" and e.get("HookType") == alias]
    assert [s for s, _ in allow_hook] == ["HOOK_IN_PROGRESS", "HOOK_COMPLETE_SUCCEEDED"], (
        f"the allow- queue's hook events for {alias!r} were {allow_hook!r}"
    )
    allow_recs = _drain_until(sqs, counter_url, records, allow_id)
    assert len(allow_recs) == 1, (
        f"the hook Lambda ran {len(allow_recs)} times for the allow- stack's create, "
        f"expected exactly 1: {allow_recs!r}"
    )
    assert allow_recs[0]["verdict"] == "SUCCESS" and allow_recs[0]["queueName"] == allow_queue, (
        f"allow- invocation record {allow_recs[0]!r}"
    )
    assert allow_recs[0]["targetName"] == "AWS::SQS::Queue", allow_recs[0]
    assert allow_recs[0]["invocationPoint"] == "CREATE_PRE_PROVISION", allow_recs[0]

    # ---- negative: a deny- queue is vetoed, rolled back, and never created ----
    deny_id = _create_stack(ctx, deny_stack, _QUEUE_TEMPLATE, {"QueueName": deny_queue})
    status = _wait_stack_terminal(ctx, deny_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"deny- stack ended in {status!r}, expected ROLLBACK_COMPLETE (CREATE_COMPLETE means "
        f"the hook's FAILED verdict was ignored): {_failure_reasons(ctx, deny_id)!r}"
    )
    events = _stack_events(ctx, deny_id)
    rollback = [e for e in events if e["LogicalResourceId"] == deny_stack
                and e.get("ResourceStatus") == "ROLLBACK_IN_PROGRESS"]
    assert len(rollback) == 1 and "[Queue]" in (rollback[0].get("ResourceStatusReason") or ""), (
        f"stack-level rollback event should blame the Queue resource: "
        f"{[(e.get('ResourceStatus'), e.get('ResourceStatusReason')) for e in rollback]!r}"
    )
    queue_events = [e for e in events if e["LogicalResourceId"] == "Queue"]
    failed = [e for e in queue_events if e.get("ResourceStatus") == "CREATE_FAILED"]
    assert len(failed) == 1, (
        f"expected one CREATE_FAILED event for the vetoed queue, got "
        f"{[(e.get('ResourceStatus'), e.get('ResourceStatusReason')) for e in queue_events]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    assert alias in reason, (
        f"the vetoed queue's StatusReason does not name the hook {alias!r}: {reason!r}"
    )
    hook_events = [e for e in queue_events if e.get("HookType") == alias]
    hook_statuses = [e.get("HookStatus") for e in hook_events]
    assert hook_statuses == ["HOOK_IN_PROGRESS", "HOOK_COMPLETE_FAILED"], (
        f"expected exactly HOOK_IN_PROGRESS then HOOK_COMPLETE_FAILED for {alias!r} on the "
        f"vetoed queue (one invocation), got {hook_statuses!r}: "
        f"{[(e.get('HookType'), e.get('HookStatus'), e.get('HookStatusReason')) for e in queue_events]!r}"
    )
    fail_ev = next(e for e in hook_events if e.get("HookStatus") == "HOOK_COMPLETE_FAILED")
    assert fail_ev.get("HookFailureMode") == "FAIL", fail_ev
    assert fail_ev.get("HookInvocationPoint") == "PRE_PROVISION", fail_ev
    assert "deny- are refused" in (fail_ev.get("HookStatusReason") or ""), (
        f"the Lambda's refusal message did not surface in HookStatusReason: {fail_ev!r}"
    )
    assert not [e for e in queue_events if e.get("ResourceStatus") == "CREATE_COMPLETE"], (
        f"the vetoed queue reached CREATE_COMPLETE at some point: "
        f"{[e.get('ResourceStatus') for e in queue_events]!r}"
    )
    code, message = _error_code(lambda: sqs.get_queue_url(QueueName=deny_queue))
    assert code == _NON_EXISTENT_QUEUE, (
        f"get_queue_url on the vetoed queue {deny_queue!r} returned {code!r}, expected "
        f"{_NON_EXISTENT_QUEUE!r} - the hook runs PRE_PROVISION so CreateQueue must never happen"
    )
    assert message == "The specified queue does not exist.", (
        f"expected the exact AWS.SimpleQueueService.NonExistentQueue message AWS returns, got {message!r}"
    )
    deny_recs = _drain_until(sqs, counter_url, records, deny_id)
    assert len(deny_recs) == 1, (
        f"the hook Lambda ran {len(deny_recs)} times for the deny- stack's create, expected "
        f"exactly 1 (not zero, not retried): {deny_recs!r}"
    )
    assert deny_recs[0]["verdict"] == "FAILED" and deny_recs[0]["queueName"] == deny_queue, (
        f"deny- invocation record {deny_recs[0]!r}"
    )

    # ---- restore: same stack name, deny- renamed to allow-, now succeeds ----
    _delete_stack_and_wait(ctx, deny_id)
    restore_id = _create_stack(ctx, deny_stack, _QUEUE_TEMPLATE, {"QueueName": restored_queue})
    assert restore_id != deny_id, f"re-created stack reused the rolled-back stack id {deny_id!r}"
    status = _wait_stack_terminal(ctx, restore_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"re-created stack with the repaired allow- name ended in {status!r}, expected "
        f"CREATE_COMPLETE: {_failure_reasons(ctx, restore_id)!r}"
    )
    restored_url = sqs.get_queue_url(QueueName=restored_queue)["QueueUrl"]
    _round_trip(sqs, restored_url)
    restore_recs = _drain_until(sqs, counter_url, records, restore_id)
    assert len(restore_recs) == 1 and restore_recs[0]["verdict"] == "SUCCESS", (
        f"restored create should invoke the hook once with SUCCESS: {restore_recs!r}"
    )
    code, message = _error_code(lambda: sqs.get_queue_url(QueueName=deny_queue))
    assert code == _NON_EXISTENT_QUEUE, (
        f"the refused deny- name resolved after the restore: {code!r}"
    )
    assert message == "The specified queue does not exist.", (
        f"expected the exact AWS.SimpleQueueService.NonExistentQueue message AWS returns, got {message!r}"
    )

    # Every invocation the Lambda ever made is accounted for by exactly these three creates.
    per_stack = [sum(1 for r in records.values() if r["stackId"] == s)
                 for s in (allow_id, deny_id, restore_id)]
    assert per_stack == [1, 1, 1] and len(records) == 3, (
        f"hook invocations not attributable one-per-create: "
        f"{[(r['stackId'], r['queueName'], r['verdict']) for r in records.values()]!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _error_code(fn) -> tuple[str, str]:
    """The ClientError code and message fn() raised. An unexpected success RAISES rather than returning a
    falsy sentinel, so an accepted call can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "<no code>"), exc.response.get("Error", {}).get("Message", "<no message>")
    raise AssertionError(f"call unexpectedly succeeded: {result!r}")


def _create_stack(ctx, name: str, template: str, parameters: dict[str, str]) -> str:
    """CreateStack and register its delete-and-wait teardown IMMEDIATELY; return the stack id."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": _MANAGED_TAG_KEY, "Value": "true"},
              {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}],
    )["StackId"]
    # Teardown ISSUES the delete and does not wait: the engine bounds the whole cleanup chain
    # (60 s), and one queue-stack delete-and-wait alone takes ~85 s, so waiting here starves
    # every teardown registered before it. CloudFormation finishes the delete server-side.
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    return stack_id


def _stack_status(ctx, stack_id: str) -> str:
    return ctx.client("cloudformation").describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _wait_stack_terminal(ctx, stack_id: str, *, timeout_s: float) -> str:
    """Poll a stack (by id) until it leaves every *_IN_PROGRESS state; return that status."""
    deadline = time.monotonic() + timeout_s
    status = "?"
    while time.monotonic() < deadline:
        status = _stack_status(ctx, stack_id)
        if not status.endswith("_IN_PROGRESS"):
            return status
        time.sleep(5.0)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s}s")


def _delete_stack_and_wait(ctx, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete a stack by id and wait for DELETE_COMPLETE. A stuck delete raises."""
    cfn = ctx.client("cloudformation")
    if _stack_status(ctx, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    try:
        status = _wait_stack_terminal(ctx, stack_id, timeout_s=timeout_s)
    except AssertionError as exc:
        print(f"stack {stack_id}: {exc}")
        raise
    if status != "DELETE_COMPLETE":
        print(f"stack {stack_id} ended delete in {status}")
        raise AssertionError(f"stack {stack_id} delete ended in {status!r}")


def _outputs(ctx, stack_id: str) -> dict[str, str]:
    stack = ctx.client("cloudformation").describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _stack_events(ctx, stack_id: str) -> list[dict[str, Any]]:
    """Every DescribeStackEvents page for a stack, oldest first."""
    cfn = ctx.client("cloudformation")
    events: list[dict[str, Any]] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page.get("StackEvents", []))
    return list(reversed(events))


def _failure_reasons(ctx, stack_id: str) -> list[tuple]:
    return [
        (e["LogicalResourceId"], e.get("ResourceStatus"), e.get("ResourceStatusReason"),
         e.get("HookType"), e.get("HookStatus"), e.get("HookStatusReason"))
        for e in _stack_events(ctx, stack_id)
        if "FAILED" in (e.get("ResourceStatus") or "") or "FAILED" in (e.get("HookStatus") or "")
    ]


def _round_trip(sqs, queue_url: str) -> None:
    """SendMessage then ReceiveMessage on the deployed queue: the body must come back intact."""
    body = f"sim2real-lh-{uuid.uuid4().hex}"
    sent = sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    got: list[dict[str, Any]] = []
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline and not got:
        got = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1,
                                  WaitTimeSeconds=10).get("Messages", [])
    assert len(got) == 1, f"no message received back from {queue_url!r} within 60s"
    assert got[0]["Body"] == body, f"received body {got[0]['Body']!r}, sent {body!r}"
    assert got[0]["MessageId"] == sent["MessageId"], (
        f"received MessageId {got[0]['MessageId']!r}, SendMessage returned {sent['MessageId']!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=got[0]["ReceiptHandle"])


def _drain_until(sqs, counter_url: str, records: dict, stack_id: str, *,
                 timeout_s: float = 120.0, quiet_polls: int = 3) -> list[dict[str, Any]]:
    """Collect every invocation record (deduped by Lambda request id, so an SQS redelivery is
    never mistaken for a hook retry) until this stack's record has arrived AND the counter
    has stayed empty for `quiet_polls` consecutive long polls. The hook is synchronous and the
    stack is already terminal, so any retry would already have been sent."""
    deadline = time.monotonic() + timeout_s
    quiet = 0
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=counter_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=5).get("Messages", [])
        for m in msgs:
            rec = json.loads(m["Body"])
            records[rec["requestId"]] = rec
            sqs.delete_message(QueueUrl=counter_url, ReceiptHandle=m["ReceiptHandle"])
        mine = [r for r in records.values() if r["stackId"] == stack_id]
        quiet = 0 if msgs else quiet + 1
        if mine and quiet >= quiet_polls:
            return mine
    return [r for r in records.values() if r["stackId"] == stack_id]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
