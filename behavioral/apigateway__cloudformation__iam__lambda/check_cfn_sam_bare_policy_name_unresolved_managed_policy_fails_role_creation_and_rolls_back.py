"""cfn-sam-bare-policy-name-unresolved-managed-policy-fails-role-creation-and-rolls-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sam-bare-policy-name-unresolved-managed-policy-fails-role-creation-and-rolls-back"

GROUP = "deploy-sam-transform"

SERVICES = ["apigateway", "cloudformation", "iam", "lambda"]

_VALID_BARE_NAME = "AmazonS3ReadOnlyAccess"
_VALID_BARE_ARN = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
_DEFAULT_BASIC_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_BOGUS_BARE_NAME = "NotARealManagedPolicyNameXyz"

_CODE = "def handler(event, context):\n    return 'ok'\n"

# CloudFormation's wrapper around a resource handler's own failure message.
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _masked(text: str) -> str:
    """``text`` with only the opaque, per-call IAM/CFN request identifiers blanked out."""
    text = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text


def _handler_reason(reason: str | None) -> tuple[str, str]:
    """``(masked message, HandlerErrorCode)`` of a resource-handler failure reason."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"]), m["code"]


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_stack_and_wait(cfn, stack_name: str, *, timeout_s=600.0) -> None:
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in msg:
                return "GONE"
            raise

    _poll_until(_status, lambda s: s in {"DELETE_COMPLETE", "GONE"}, timeout_s=timeout_s,
                interval_s=5.0, description=f"delete stack {stack_name}")


def _wait_terminal(cfn, stack_name: str, *, timeout_s=300.0) -> str:
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith(("_COMPLETE", "_FAILED")),
        timeout_s=timeout_s, interval_s=5.0, description=f"stack {stack_name}",
    )


def _function_only_template(fn_name: str, bare_name: str) -> str:
    return json.dumps({
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "Fn": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "InlineCode": _CODE,
                    "Policies": [bare_name],
                },
            },
        },
    })


def _heterogeneous_template(fn_name: str, api_name: str, stage_name: str, bare_name: str) -> str:
    """The function from the control, plus a REST API with no relation to IAM at all."""
    t = json.loads(_function_only_template(fn_name, bare_name))
    t["Resources"]["RestApi"] = {
        "Type": "AWS::ApiGateway::RestApi",
        "Properties": {"Name": api_name, "EndpointConfiguration": {"Types": ["REGIONAL"]}},
    }
    t["Resources"]["Resource"] = {
        "Type": "AWS::ApiGateway::Resource",
        "Properties": {
            "RestApiId": {"Ref": "RestApi"},
            "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
            "PathPart": "widgets",
        },
    }
    t["Resources"]["Method"] = {
        "Type": "AWS::ApiGateway::Method",
        "Properties": {
            "RestApiId": {"Ref": "RestApi"},
            "ResourceId": {"Ref": "Resource"},
            "HttpMethod": "GET",
            "AuthorizationType": "NONE",
            "Integration": {
                "Type": "MOCK",
                "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                "IntegrationResponses": [{"StatusCode": "200"}],
            },
            "MethodResponses": [{"StatusCode": "200"}],
        },
    }
    t["Resources"]["Deployment"] = {
        "Type": "AWS::ApiGateway::Deployment",
        "DependsOn": "Method",
        "Properties": {"RestApiId": {"Ref": "RestApi"}, "StageName": stage_name},
    }
    return json.dumps(t)


def _attached_arns(iam, role_name: str) -> list[str]:
    return sorted(
        p["PolicyArn"]
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name)
        for p in page["AttachedPolicies"]
    )


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A bare Policies string naming no real managed policy is passed through unmodified into
    ManagedPolicyArns; IAM refuses to attach it, failing the whole stack at CREATE time -- not
    at transform time -- and rolling back every resource, including ones unrelated to IAM.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    awslambda = ctx.client("lambda")
    ag = ctx.client("apigateway")

    # ---- control: the identical shape with a resolvable bare name must succeed --------------
    control_fn = ctx.unique_name("sim2real-xsvc-fn-")
    control_stack = ctx.unique_name("sim2real-xsvc-stk-")
    cfn.create_stack(
        StackName=control_stack,
        TemplateBody=_function_only_template(control_fn, _VALID_BARE_NAME),
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, control_stack))
    control_status = _wait_terminal(cfn, control_stack)
    assert control_status == "CREATE_COMPLETE", (
        f"control: {_VALID_BARE_NAME!r} must resolve and the stack must succeed; got "
        f"{control_status!r}"
    )
    control_role = next(
        r["PhysicalResourceId"]
        for r in cfn.list_stack_resources(StackName=control_stack)["StackResourceSummaries"]
        if r["LogicalResourceId"] == "FnRole"
    )
    assert _attached_arns(iam, control_role) == sorted([_DEFAULT_BASIC_ARN, _VALID_BARE_ARN]), (
        f"control: role {control_role!r} must carry the resolved {_VALID_BARE_ARN!r} beside "
        f"the default; got {_attached_arns(iam, control_role)!r}"
    )
    _delete_stack_and_wait(cfn, control_stack)

    # ---- the one property changed: a bare name IAM has never heard of ----------------------
    bad_fn = ctx.unique_name("sim2real-xsvc-fn-")
    api_name = ctx.unique_name("sim2real-xsvc-api-")
    bad_stack = ctx.unique_name("sim2real-xsvc-stk-")
    stage_name = "s" + ctx.unique_name("")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_heterogeneous_template(bad_fn, api_name, stage_name, _BOGUS_BARE_NAME),
        Capabilities=["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack))
    bad_status = _wait_terminal(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"an unresolvable bare Policies name must fail the stack to ROLLBACK_COMPLETE, not "
        f"{bad_status!r}"
    )

    # ---- the SAM transform passed the bogus name through unmodified ------------------------
    processed = cfn.get_template(StackName=bad_stack, TemplateStage="Processed")["TemplateBody"]
    processed = json.loads(processed) if isinstance(processed, str) else processed
    managed_arns = processed["Resources"]["FnRole"]["Properties"]["ManagedPolicyArns"]
    assert sorted(managed_arns) == sorted([_DEFAULT_BASIC_ARN, _BOGUS_BARE_NAME]), (
        "the transform must emit the unrecognized bare name verbatim (no ARN prefix added), "
        f"beside the default basic-execution ARN; Processed template has {managed_arns!r}"
    )

    # ---- IAM's own refusal is what actually failed the stack --------------------------------
    events = cfn.describe_stack_events(StackName=bad_stack)["StackEvents"]
    role_failure = next(
        e["ResourceStatusReason"] for e in events
        if e["LogicalResourceId"] == "FnRole" and e["ResourceStatus"] == "CREATE_FAILED"
    )
    message, handler_code = _handler_reason(role_failure)
    assert handler_code == "InvalidRequest", (
        f"expected HandlerErrorCode InvalidRequest, got {handler_code!r} in {role_failure!r}"
    )
    assert message == (
        f"ARN {_BOGUS_BARE_NAME} is not valid. (Service: Iam, Status Code: 400, "
        "Request ID: <id>) (SDK Attempt Count: <n>)"
    ), f"unexpected masked IAM failure message: {message!r}"

    # ---- a resource with no relation to IAM is rolled back too ------------------------------
    resources = {
        r["LogicalResourceId"]: r
        for r in cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    }
    statuses = {name: r["ResourceStatus"] for name, r in resources.items()}
    assert statuses["FnRole"] == "DELETE_COMPLETE" and statuses["RestApi"] == "DELETE_COMPLETE", (
        f"the failed role and the unrelated RestApi must both be rolled back; got {statuses!r}"
    )
    assert set(statuses.values()) == {"DELETE_COMPLETE"}, (
        f"every resource the stack started must be rolled back; got {statuses!r}"
    )
    api_id = resources["RestApi"]["PhysicalResourceId"]

    _delete_stack_and_wait(cfn, bad_stack)

    code, message = _error(lambda: awslambda.get_function(FunctionName=bad_fn))
    assert (code, message) == (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn}",
    ), f"the function must never exist; got {code}: {message!r}"
    code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert (code, message) == (
        "NotFoundException", f"Invalid API identifier specified {ctx.account}:{api_id}",
    ), f"the rolled-back REST API must be gone; got {code}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
