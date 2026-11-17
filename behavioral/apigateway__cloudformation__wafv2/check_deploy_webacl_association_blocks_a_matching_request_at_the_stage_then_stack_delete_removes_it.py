"""deploy-webacl-association-blocks-a-matching-request-at-the-stage-then-stack-delete-removes-it."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-webacl-association-blocks-a-matching-request-at-the-stage-then-stack-delete-removes-it"
GROUP = "cloudformation"
SERVICES = ["apigateway", "cloudformation", "wafv2"]

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_STACK_BUDGET_S = 300.0
_SERVE_BUDGET_S = 180.0
_BLOCK_HEADER = "x-sim2real-block"
_BLOCK_VALUE = "trip-the-rule"


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


def _stack_status(cfn, stack_name):
    return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]


def _stack_status_or_gone(cfn, stack_name):
    """``_stack_status``, but a name DescribeStacks no longer resolves reads as DELETE_COMPLETE.

    CloudFormation stops resolving a stack by its (non-ARN) name the instant deletion finishes,
    so polling for DELETE_COMPLETE by name would otherwise never see that status.
    """
    try:
        return _stack_status(cfn, stack_name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationError" and "does not exist" in (err.get("Message") or ""):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(cfn, stack_name):
    """Delete the stack and wait for DELETE_COMPLETE; raise naming the failed resources.

    Safe to call twice: a stack this check already deleted is nothing to delete.
    """
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


def _invoke_policy(ctx) -> str:
    """A resource policy admitting execute-api:Invoke only from the runner's own egress."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "execute-api:Invoke",
            "Resource": "execute-api:/*",
            "Condition": {"IpAddress": {"aws:SourceIp": ctx.ingress_cidrs()}},
        }],
    })


def _template(*, api_name: str, stage_name: str, webacl_name: str, policy: str) -> str:
    """A REGIONAL REST API with a MOCK method, and a REGIONAL WebACL blocking one header value,
    associated with the API's stage."""
    return json.dumps({
        "Resources": {
            "RestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Name": api_name,
                    "EndpointConfiguration": {"Types": ["REGIONAL"]},
                    "Policy": policy,
                },
            },
            "Resource": {
                "Type": "AWS::ApiGateway::Resource",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ParentId": {"Fn::GetAtt": ["RestApi", "RootResourceId"]},
                    "PathPart": "ping",
                },
            },
            "Method": {
                "Type": "AWS::ApiGateway::Method",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResourceId": {"Ref": "Resource"},
                    "HttpMethod": "GET",
                    "AuthorizationType": "NONE",
                    "Integration": {
                        "Type": "MOCK",
                        "RequestTemplates": {"application/json": '{"statusCode": 200}'},
                        "IntegrationResponses": [
                            {"StatusCode": "200",
                             "ResponseTemplates": {"application/json": '{"served": true}'}},
                        ],
                    },
                    "MethodResponses": [{"StatusCode": "200"}],
                },
            },
            "Deployment": {
                "Type": "AWS::ApiGateway::Deployment",
                "DependsOn": "Method",
                "Properties": {"RestApiId": {"Ref": "RestApi"}, "StageName": stage_name},
            },
            "WebAcl": {
                "Type": "AWS::WAFv2::WebACL",
                "Properties": {
                    "Name": webacl_name,
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": False,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": webacl_name.replace("-", ""),
                    },
                    "Rules": [{
                        "Name": "BlockOnHeader",
                        "Priority": 0,
                        "Action": {"Block": {}},
                        "Statement": {
                            "ByteMatchStatement": {
                                "SearchString": _BLOCK_VALUE,
                                "FieldToMatch": {"SingleHeader": {"Name": _BLOCK_HEADER}},
                                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                "PositionalConstraint": "EXACTLY",
                            },
                        },
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": False,
                            "CloudWatchMetricsEnabled": False,
                            "MetricName": webacl_name.replace("-", "") + "rule",
                        },
                    }],
                },
            },
            "WebAclAssociation": {
                "Type": "AWS::WAFv2::WebACLAssociation",
                "DependsOn": "Deployment",
                "Properties": {
                    "ResourceArn": {"Fn::Sub":
                        f"arn:aws:apigateway:${{AWS::Region}}::/restapis/${{RestApi}}/stages/{stage_name}"},
                    "WebACLArn": {"Fn::GetAtt": ["WebAcl", "Arn"]},
                },
            },
        },
    })


def _ssl_context(verify):
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _get(url: str, verify, *, headers: dict | None = None) -> tuple[int | None, str]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=20, context=_ssl_context(verify)) as resp:  # noqa: S310
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to fail, but it returned: {result!r}")


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:deploy", "concern:data-plane",
      "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A REGIONAL WebACL that CloudFormation associates with a REST API stage blocks a request
    matching its rule and lets an unmatched request through; deleting the stack removes both the
    API and the association.
    """
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    wafv2 = ctx.client("wafv2")

    api_name = ctx.unique_name("sim2real-xsvc-api-")
    webacl_name = ctx.unique_name("sim2real-xsvc-acl-")
    stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    stage_name = "live"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(api_name=api_name, stage_name=stage_name, webacl_name=webacl_name,
                                policy=_invoke_policy(ctx)),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    status = _poll_until(lambda: _stack_status(cfn, stack_name),
                          lambda s: s in _STACK_TERMINAL,
                          timeout_s=_STACK_BUDGET_S, description=f"stack {stack_name} create")
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, not CREATE_COMPLETE"

    resources = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    }
    api_id = resources["RestApi"]
    # the physical resource id for AWS::WAFv2::WebACL is "Name|Id|Scope"
    webacl_id = resources["WebAcl"].split("|")[1]

    stage = ag.get_stage(restApiId=api_id, stageName=stage_name)
    assert stage["deploymentId"] == resources["Deployment"], (
        f"stage {stage_name!r} must point at the Deployment resource {resources['Deployment']!r}; "
        f"GetStage reported deploymentId {stage['deploymentId']!r}"
    )

    url = f"{ctx.rest_api_url(api_id, stage_name)}/ping"

    # ---- the stage serves the unmatched request once the deployment has propagated -----------
    status_code, body = _poll_until(
        lambda: _get(url, ctx.http_verify),
        lambda r: r[0] == 200,
        timeout_s=_SERVE_BUDGET_S, description="the deployed stage serving its MOCK integration",
    )
    assert status_code == 200, f"GET {url} returned status {status_code!r}, body {body[:200]!r}"
    assert json.loads(body) == {"served": True}, f"GET {url} returned body {body!r}"

    # ---- the associated WebACL blocks a request matching its rule's byte-match condition -------
    blocked_status, blocked_body = _poll_until(
        lambda: _get(url, ctx.http_verify, headers={_BLOCK_HEADER: _BLOCK_VALUE}),
        lambda r: r[0] == 403,
        timeout_s=_SERVE_BUDGET_S, description="the WebACL association blocking the matching header",
    )
    assert blocked_status == 403, (
        f"GET {url} with {_BLOCK_HEADER}: {_BLOCK_VALUE!r} returned status {blocked_status!r}, "
        f"body {blocked_body[:200]!r}, expected 403 from the WebACL's Block rule"
    )
    assert blocked_body == '{"message":"Forbidden"}', (
        f'a Block rule with no CustomResponse answers {{"message":"Forbidden"}}; '
        f"got {blocked_body[:200]!r}"
    )

    # ---- the unmatched request still passes while the rule is in effect (control, same wiring) --
    control_status, control_body = _get(url, ctx.http_verify)
    assert control_status == 200, (
        f"GET {url} with no blocking header returned {control_status!r} after the blocked probe; "
        f"the WebACL's rule must only match its own header"
    )
    assert json.loads(control_body) == {"served": True}, f"GET {url} returned body {control_body!r}"

    # ---- deleting the stack removes the API and the WebACL it provisioned ---------------------
    _delete_stack(cfn, stack_name)

    code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert code == "NotFoundException", f"expected the REST API gone, got {code}: {message!r}"
    assert message == f"Invalid API identifier specified {ctx.account}:{api_id}", (
        f"unexpected not-found message for the deleted REST API: {message!r}"
    )

    code, message = _error(lambda: wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id))
    assert code == "WAFNonexistentItemException", (
        f"expected the WebACL gone, got {code}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
