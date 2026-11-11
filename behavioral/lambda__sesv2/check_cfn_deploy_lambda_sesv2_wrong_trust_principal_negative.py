"""cfn-deploy-lambda-sesv2-wrong-trust-principal-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-sesv2-wrong-trust-principal-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "sesv2"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction refuses a role trusting ec2.amazonaws.com (InvalidParameterValueException,
    exact message) and no function exists, while a role trusting lambda.amazonaws.com with the
    same policy creates a function whose SendEmail reaches SES's MessageRejected (exact message)."""
    lam = ctx.client("lambda")
    from_address = f"{ctx.unique_name('sim2real-ses-')}@example.com"

    # --- broken: role trusts ec2.amazonaws.com, not lambda.amazonaws.com ---
    bad_role_arn = _create_role(ctx, principal="ec2.amazonaws.com")
    bad_fn_name = ctx.unique_name("sim2real-xsvc-fn-bad-")

    code, message = _expect_create_function_rejected(
        ctx,
        lam,
        FunctionName=bad_fn_name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=bad_role_arn,
        Timeout=20,
        Environment={"Variables": {"FROM_ADDRESS": from_address}},
        Code={"ZipFile": _make_zip(_SEND_EMAIL_LAMBDA_CODE)},
    )
    assert code == "InvalidParameterValueException", code
    expected_message = "The role defined for the function cannot be assumed by Lambda."
    assert message == expected_message, f"{message!r} != {expected_message!r}"

    # effect absent: the function was never created
    not_found_code, not_found_message = _error(lambda: lam.get_function(FunctionName=bad_fn_name))
    assert not_found_code == "ResourceNotFoundException", not_found_code
    expected_not_found = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn_name}"
    )
    assert not_found_message == expected_not_found, (
        f"{not_found_message!r} != {expected_not_found!r}"
    )

    # --- positive control: same setup, correct trust principal ---
    good_role_arn = _create_role(ctx, principal="lambda.amazonaws.com")
    good_fn_name = ctx.unique_name("sim2real-xsvc-fn-good-")

    def _try_create():
        return lam.create_function(
            FunctionName=good_fn_name,
            Runtime="python3.12",
            Handler="index.handler",
            Role=good_role_arn,
            Timeout=20,
            Environment={"Variables": {"FROM_ADDRESS": from_address}},
            Code={"ZipFile": _make_zip(_SEND_EMAIL_LAMBDA_CODE)},
        )

    # IAM role propagation can occasionally still be lagging even after the wait in
    # _create_role; retry the (legitimately assumable) role for a bit before giving up.
    create_resp = None
    deadline = time.monotonic() + 60
    while create_resp is None:
        try:
            create_resp = _try_create()
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, good_fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=good_fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=good_fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {good_fn_name} Active",
    )
    assert create_resp["FunctionName"] == good_fn_name, create_resp

    invoke_resp = lam.invoke(FunctionName=good_fn_name, Payload=b"{}")
    assert "FunctionError" not in invoke_resp, invoke_resp.get("FunctionError")
    payload = json.loads(invoke_resp["Payload"].read())
    assert payload["outcome"] == "error", payload
    assert payload["errorCode"] == "MessageRejected", payload
    expected_rejection = (
        "Email address is not verified. The following identities failed "
        f"the check in region {ctx.region.upper()}: {from_address}"
    )
    assert payload["errorMessage"] == expected_rejection, (
        f"{payload!r} != {expected_rejection!r}"
    )


_SEND_EMAIL_LAMBDA_CODE = """
import json
import os
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("sesv2")
    from_address = os.environ["FROM_ADDRESS"]
    try:
        resp = client.send_email(
            FromEmailAddress=from_address,
            Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
            Content={
                "Simple": {
                    "Subject": {"Data": "sim2real test"},
                    "Body": {"Text": {"Data": "sim2real test body"}},
                }
            },
        )
        return {"outcome": "sent", "messageId": resp.get("MessageId")}
    except ClientError as e:
        return {
            "outcome": "error",
            "errorCode": e.response["Error"]["Code"],
            "errorMessage": e.response["Error"]["Message"],
        }
""".strip()


_XSVC_PREFIX = "sim2real-xsvc-"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _make_zip(handler_source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_source)
    return buf.getvalue()


def _expect_create_function_rejected(ctx, lam, **kwargs) -> tuple[str, str]:
    """Call create_function expecting a synchronous rejection."""
    try:
        lam.create_function(**kwargs)
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, kwargs["FunctionName"]))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=kwargs["FunctionName"]))
    raise AssertionError(
        f"create_function unexpectedly succeeded for {kwargs['FunctionName']!r} with role {kwargs['Role']!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _create_role(ctx, *, principal: str) -> str:
    """CFN-deploy an IAM role with the given trust-policy principal and an ses:SendEmail
    policy. IAM's eventual-consistency window (when the principal is actually
    lambda.amazonaws.com) is the caller's problem to bound with a retry, not this
    function's to paper over with a sleep."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    stack_name = _xname(ctx, "role-stk")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": principal},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "SesSendEmailAndLogs",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["ses:SendEmail", "ses:SendRawEmail"],
                                            "Resource": "*",
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "logs:CreateLogGroup",
                                                "logs:CreateLogStream",
                                                "logs:PutLogEvents",
                                            ],
                                            "Resource": "*",
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                }
            },
            "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}}},
        }
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM"],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"},
        timeout_s=120,
        interval_s=3.0,
        description=f"CFN role stack {stack_name}",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"role stack {stack_name} ended in {stack['StackStatus']}")
    arn = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}["RoleArn"]
    # IAM writes are eventually consistent; the caller's own retry loop (for the "good"
    # role) bounds the wait for the assumability check to catch up rather than sleeping here.
    return arn


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two reads 5 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
