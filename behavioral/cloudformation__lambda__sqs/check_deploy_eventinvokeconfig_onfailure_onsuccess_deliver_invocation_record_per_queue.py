"""deploy-eventinvokeconfig-onfailure-onsuccess-deliver-invocation-record-per-queue."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eventinvokeconfig-onfailure-onsuccess-deliver-invocation-record-per-queue"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "lambda", "sqs"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_STACK_BUDGET_S = 300.0
_DELIVERY_BUDGET_S = 180.0

_CODE = (
    "def handler(event, context):\n"
    "    if event.get('fail'):\n"
    "        raise RuntimeError('induced-failure')\n"
    "    return {'ok': True, 'marker': event.get('marker')}\n"
)


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll ``probe()`` until ``predicate`` holds; raise naming the last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s:.0f}s; last was {last!r}")


def _stack_status_or_gone(cfn, stack_name):
    """A stack's status, reading a name DescribeStacks no longer resolves as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationError" and "does not exist" in (err.get("Message") or ""):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(cfn, stack_name):
    """Delete the stack and wait for DELETE_COMPLETE; raise naming the failed resources."""
    status = _stack_status_or_gone(cfn, stack_name)
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS"):
        _poll_until(lambda: _stack_status_or_gone(cfn, stack_name), lambda s: s in _STACK_TERMINAL,
                    timeout_s=_STACK_BUDGET_S, description=f"stack {stack_name} settling")
    cfn.delete_stack(StackName=stack_name)
    final = _poll_until(lambda: _stack_status_or_gone(cfn, stack_name),
                         lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED"},
                         timeout_s=_STACK_BUDGET_S, description=f"stack {stack_name} delete")
    if final != "DELETE_COMPLETE":
        reasons = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                   for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
                   if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_name} delete ended {final!r}: {reasons!r}")


def _template(*, fn_name: str) -> str:
    """A Lambda function whose EventInvokeConfig routes failed async invocations to one SQS
    queue and successful ones to another."""
    return json.dumps({
        "Resources": {
            "QueueFailure": {"Type": "AWS::SQS::Queue", "Properties": {}},
            "QueueSuccess": {"Type": "AWS::SQS::Queue", "Properties": {}},
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                    ],
                    "Policies": [{
                        "PolicyName": "send-invocation-records",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "sqs:SendMessage",
                                "Resource": [
                                    {"Fn::GetAtt": ["QueueFailure", "Arn"]},
                                    {"Fn::GetAtt": ["QueueSuccess", "Arn"]},
                                ],
                            }],
                        },
                    }],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 10,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": _CODE},
                },
            },
            "InvokeConfig": {
                "Type": "AWS::Lambda::EventInvokeConfig",
                "DependsOn": "Fn",
                "Properties": {
                    "FunctionName": {"Ref": "Fn"},
                    "Qualifier": "$LATEST",
                    "MaximumRetryAttempts": 0,
                    "MaximumEventAgeInSeconds": 60,
                    "DestinationConfig": {
                        "OnFailure": {"Destination": {"Fn::GetAtt": ["QueueFailure", "Arn"]}},
                        "OnSuccess": {"Destination": {"Fn::GetAtt": ["QueueSuccess", "Arn"]}},
                    },
                },
            },
        },
    })


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it returned: {result!r}")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered stream from a just-deleted function can flush and recreate its log group, so one
    delete is not a teardown; raises if it is still coming back when ``budget_s`` runs out.
    """
    deadline = time.monotonic() + budget_s
    clean_reads = 0
    while clean_reads < reads:
        present = any(
            g["logGroupName"] == name
            for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        )
        if present:
            clean_reads = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            clean_reads += 1
        if clean_reads < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still reappearing after {budget_s:.0f}s of deletes"
                )
            time.sleep(interval_s)


def _receive_one(sqs, queue_url: str):
    """One message body from ``queue_url``, or ``None`` within one short long-poll wait."""
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    messages = resp.get("Messages", [])
    if not messages:
        return None
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
    return json.loads(messages[0]["Body"])


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:eventing", "concern:data-plane",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-provisioned EventInvokeConfig delivers a failed async invocation's record
    to its OnFailure queue, and a successful one's to its OnSuccess queue.
    """
    cfn = ctx.client("cloudformation")
    awslambda = ctx.client("lambda")
    sqs = ctx.client("sqs")
    logs = ctx.client("logs")

    fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    stack_name = ctx.unique_name("sim2real-xsvc-stk-")

    # registered before create, so LIFO reaps the log group after the stack (and the function
    # it provisions) is already deleted — a buffered stream can recreate it right after
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn_name}"))

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(fn_name=fn_name),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    status = _poll_until(lambda: _stack_status_or_gone(cfn, stack_name),
                          lambda s: s in _STACK_TERMINAL,
                          timeout_s=_STACK_BUDGET_S, description=f"stack {stack_name} create")
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, not CREATE_COMPLETE"

    resources = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    }
    failure_queue_url = resources["QueueFailure"]
    success_queue_url = resources["QueueSuccess"]

    # ---- a failing async invocation's record lands on the OnFailure queue ---------------------
    fail_marker = ctx.unique_name("fail-")
    awslambda.invoke(FunctionName=fn_name, InvocationType="Event",
                      Payload=json.dumps({"fail": True, "marker": fail_marker}).encode())

    record = _poll_until(lambda: _receive_one(sqs, failure_queue_url),
                          lambda r: r is not None,
                          timeout_s=_DELIVERY_BUDGET_S, interval_s=2.0,
                          description="the OnFailure queue receiving the invocation record")
    assert record["requestPayload"] == {"fail": True, "marker": fail_marker}, (
        f"the OnFailure record's requestPayload must echo the invoke payload; got "
        f"{record['requestPayload']!r}"
    )
    assert record["requestContext"]["condition"] == "RetriesExhausted", (
        f"with MaximumRetryAttempts=0 a failed invoke reports condition 'RetriesExhausted'; got "
        f"{record['requestContext']['condition']!r}"
    )
    assert record["requestContext"]["approximateInvokeCount"] == 1, (
        f"zero configured retries means exactly one invocation attempt; "
        f"approximateInvokeCount was {record['requestContext']['approximateInvokeCount']!r}"
    )
    assert record["responseContext"]["functionError"] == "Unhandled", (
        f"an uncaught exception in the handler reports functionError 'Unhandled'; got "
        f"{record['responseContext']['functionError']!r}"
    )
    assert record["responsePayload"]["errorMessage"] == "induced-failure", (
        f"the response payload must carry the raised exception's message; got "
        f"{record['responsePayload']['errorMessage']!r}"
    )
    assert record["responsePayload"]["errorType"] == "RuntimeError", (
        f"the response payload must carry the raised exception's type; got "
        f"{record['responsePayload']['errorType']!r}"
    )

    # ---- a successful async invocation's record lands on the OnSuccess queue (control) --------
    ok_marker = ctx.unique_name("ok-")
    awslambda.invoke(FunctionName=fn_name, InvocationType="Event",
                      Payload=json.dumps({"fail": False, "marker": ok_marker}).encode())

    ok_record = _poll_until(lambda: _receive_one(sqs, success_queue_url),
                             lambda r: r is not None,
                             timeout_s=_DELIVERY_BUDGET_S, interval_s=2.0,
                             description="the OnSuccess queue receiving the invocation record")
    assert ok_record["requestPayload"] == {"fail": False, "marker": ok_marker}, (
        f"the OnSuccess record's requestPayload must echo the invoke payload; got "
        f"{ok_record['requestPayload']!r}"
    )
    assert "functionError" not in ok_record["responseContext"], (
        f"a successful invocation's responseContext carries no functionError; got "
        f"{ok_record['responseContext']!r}"
    )
    assert ok_record["responsePayload"] == {"ok": True, "marker": ok_marker}, (
        f"the OnSuccess record's responsePayload must be the handler's return value; got "
        f"{ok_record['responsePayload']!r}"
    )

    _delete_stack(cfn, stack_name)

    code, message = _error(lambda: awslambda.get_function(FunctionName=fn_name))
    assert (code, message) == (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}",
    ), f"expected the function gone, got {code}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
