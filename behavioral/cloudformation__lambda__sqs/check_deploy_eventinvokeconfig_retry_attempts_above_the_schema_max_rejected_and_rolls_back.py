"""deploy-eventinvokeconfig-retry-attempts-above-the-schema-max-rejected-and-rolls-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eventinvokeconfig-retry-attempts-above-the-schema-max-rejected-and-rolls-back"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "lambda", "sqs"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
})
_STACK_BUDGET_S = 300.0

_CODE = "def handler(event, context):\n    return event\n"


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
    cfn.delete_stack(StackName=stack_name)
    final = _poll_until(lambda: _stack_status_or_gone(cfn, stack_name),
                         lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED"},
                         timeout_s=_STACK_BUDGET_S, description=f"stack {stack_name} delete")
    if final != "DELETE_COMPLETE":
        reasons = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                   for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
                   if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_name} delete ended {final!r}: {reasons!r}")


def _template(*, fn_name: str, max_retry_attempts: int) -> str:
    """A Lambda function with an EventInvokeConfig whose MaximumRetryAttempts is given."""
    return json.dumps({
        "Resources": {
            "QueueFailure": {"Type": "AWS::SQS::Queue", "Properties": {}},
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
                        "PolicyName": "send-to-failure-destination",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["QueueFailure", "Arn"]},
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
                    "MaximumRetryAttempts": max_retry_attempts,
                    "DestinationConfig": {
                        "OnFailure": {"Destination": {"Fn::GetAtt": ["QueueFailure", "Arn"]}},
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


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CloudFormation rejects an EventInvokeConfig whose MaximumRetryAttempts exceeds the
    model's maximum of 2 and rolls the whole stack back, leaving no function or queue behind.
    """
    cfn = ctx.client("cloudformation")
    awslambda = ctx.client("lambda")

    # ---- positive control: the boundary value 2 deploys cleanly --------------------------------
    good_fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    good_stack_name = ctx.unique_name("sim2real-xsvc-stk-")

    cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=_template(fn_name=good_fn_name, max_retry_attempts=2),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack_name))

    good_status = _poll_until(lambda: _stack_status_or_gone(cfn, good_stack_name),
                               lambda s: s in _STACK_TERMINAL,
                               timeout_s=_STACK_BUDGET_S, description=f"stack {good_stack_name}")
    if good_status != "CREATE_COMPLETE":
        diag = [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
                for e in cfn.describe_stack_events(StackName=good_stack_name)["StackEvents"]]
        raise AssertionError(
            f"the control stack {good_stack_name!r} (MaximumRetryAttempts=2) ended "
            f"{good_status!r}, not CREATE_COMPLETE; events: {diag!r}"
        )
    good_config = awslambda.get_function_event_invoke_config(
        FunctionName=good_fn_name, Qualifier="$LATEST")
    assert good_config["MaximumRetryAttempts"] == 2, (
        f"the control EventInvokeConfig must read back MaximumRetryAttempts=2; got "
        f"{good_config['MaximumRetryAttempts']!r}"
    )

    # ---- break exactly one thing: MaximumRetryAttempts one past the model's maximum of 2 -------
    bad_fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    bad_stack_name = ctx.unique_name("sim2real-xsvc-stk-")

    cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=_template(fn_name=bad_fn_name, max_retry_attempts=3),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack_name))

    bad_status = _poll_until(lambda: _stack_status_or_gone(cfn, bad_stack_name),
                              lambda s: s in _STACK_TERMINAL,
                              timeout_s=_STACK_BUDGET_S, description=f"stack {bad_stack_name}")
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"an EventInvokeConfig with MaximumRetryAttempts=3 must fail the stack and roll it "
        f"back; {bad_stack_name!r} ended {bad_status!r}"
    )

    events = cfn.describe_stack_events(StackName=bad_stack_name)["StackEvents"]
    failed = [e for e in events
              if e["LogicalResourceId"] == bad_stack_name and e["ResourceStatus"] == "CREATE_FAILED"]
    assert failed, f"expected a stack-level CREATE_FAILED event; events were {events!r}"
    expected_reason = (
        "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
        "issues with resource and property details, resolve each error, then retry the "
        "operation."
    )
    assert failed[0]["ResourceStatusReason"] == expected_reason, (
        f"a MaximumRetryAttempts over the model's maximum fails template validation before any "
        f"resource is touched, with the reason {expected_reason!r}; got "
        f"{failed[0]['ResourceStatusReason']!r}"
    )
    assert failed[0].get("DetailedStatus") == "VALIDATION_FAILED", (
        f"expected DetailedStatus VALIDATION_FAILED on the stack-level failure; got "
        f"{failed[0].get('DetailedStatus')!r}"
    )

    # ---- the effect is absent: the function the same template requested was never left behind --
    code, message = _error(lambda: awslambda.get_function(FunctionName=bad_fn_name))
    assert (code, message) == (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn_name}",
    ), f"expected the rolled-back stack's function gone, got {code}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
