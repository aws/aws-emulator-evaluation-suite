"""deploy-apigateway-documentation-and-gateway-response-round-trip."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigateway-documentation-and-gateway-response-round-trip"
GROUP = "deploy"
SERVICES = ["apigateway", "cloudformation"]

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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_RESPONSE_TYPE = "DEFAULT_4XX"
_STATUS_CODE = "404"


def _template(api_name: str, doc_description: str, dv_description: str, response_template: str,
              with_children: bool = True) -> str:
    resources = {
        "RestApi": {
            "Type": "AWS::ApiGateway::RestApi",
            "Properties": {"Name": api_name, "EndpointConfiguration": {"Types": ["REGIONAL"]}},
        },
    }
    outputs = {
        "RestApiRef": {"Value": {"Ref": "RestApi"}},
        "RootResourceId": {"Value": {"Fn::GetAtt": ["RestApi", "RootResourceId"]}},
    }
    if with_children:
        resources.update({
            "GatewayResponse": {
                "Type": "AWS::ApiGateway::GatewayResponse",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "ResponseType": _RESPONSE_TYPE,
                    "StatusCode": _STATUS_CODE,
                    "ResponseTemplates": {"application/json": response_template},
                },
            },
            "DocumentationPart": {
                "Type": "AWS::ApiGateway::DocumentationPart",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "Location": {"Type": "API"},
                    "Properties": json.dumps({"description": doc_description}),
                },
            },
            "DocumentationVersion": {
                "Type": "AWS::ApiGateway::DocumentationVersion",
                "DependsOn": "DocumentationPart",
                "Properties": {
                    "RestApiId": {"Ref": "RestApi"},
                    "DocumentationVersion": "1.0",
                    "Description": dv_description,
                },
            },
        })
        outputs.update({
            "GatewayResponseRef": {"Value": {"Ref": "GatewayResponse"}},
            "DocumentationPartRef": {"Value": {"Ref": "DocumentationPart"}},
            "DocumentationPartId": {
                "Value": {"Fn::GetAtt": ["DocumentationPart", "DocumentationPartId"]}},
            "DocumentationVersionRef": {"Value": {"Ref": "DocumentationVersion"}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation GatewayResponse, DocumentationPart and DocumentationVersion read back.

    Every templated property, Ref and GetAtt matches; an update dropping them leaves the live API its
    default response and no documentation, and the stack delete makes the API NotFound.
    """
    cfn = ctx.client("cloudformation")
    ag = ctx.client("apigateway")
    api_name = ctx.unique_name("sim2real-cfnagwdoc-restapi-")
    doc_description = ctx.unique_name("sim2real-cfnagwdoc-dp-")
    dv_description = ctx.unique_name("sim2real-cfnagwdoc-dv-")
    response_template = json.dumps({"message": ctx.unique_name("sim2real-cfnagwdoc-gr-")})
    args = (api_name, doc_description, dv_description, response_template)

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnagwdoc-"), _template(*args))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    api_id = out["RestApiRef"]

    # RestApi: Ref against the API listed under its name; RootResourceId against GetResources.
    apis = [a for a in paginate(ag, "get_rest_apis", "items") if a["name"] == api_name]
    assert [a["id"] for a in apis] == [api_id], f"APIs named {api_name!r}: {apis!r}"
    assert apis[0]["endpointConfiguration"]["types"] == ["REGIONAL"], f"API reads {apis[0]!r}"
    root = [r["id"] for r in paginate(ag, "get_resources", "items", restApiId=api_id)
            if r["path"] == "/"]
    assert root == [out["RootResourceId"]], f"root resource {root!r}, GetAtt {out['RootResourceId']!r}"

    assert out["GatewayResponseRef"] == f"{api_id}:{_RESPONSE_TYPE}", (
        f"Ref(GatewayResponse) {out['GatewayResponseRef']!r}"
    )
    gr = ag.get_gateway_response(restApiId=api_id, responseType=_RESPONSE_TYPE)
    got = (gr["responseType"], gr["statusCode"], gr["responseTemplates"], gr["defaultResponse"])
    want = (_RESPONSE_TYPE, _STATUS_CODE, {"application/json": response_template}, False)
    assert got == want, f"gateway response reads {got!r}, expected {want!r}"

    # DocumentationPart: Ref and GetAtt against the API's only documentation part.
    parts = paginate(ag, "get_documentation_parts", "items", restApiId=api_id)
    got = [(p["id"], p["location"], p["properties"]) for p in parts]
    want = [(out["DocumentationPartRef"], {"type": "API"},
             json.dumps({"description": doc_description}))]
    assert got == want, f"documentation parts {got!r}, expected {want!r}"
    assert out["DocumentationPartId"] == out["DocumentationPartRef"], (
        f"GetAtt DocumentationPartId {out['DocumentationPartId']!r}"
    )

    assert out["DocumentationVersionRef"] == f"1.0|{api_id}", (
        f"Ref(DocumentationVersion) {out['DocumentationVersionRef']!r}"
    )
    versions = paginate(ag, "get_documentation_versions", "items", restApiId=api_id)
    got = [(v["version"], v["description"]) for v in versions]
    assert got == [("1.0", dv_description)], f"documentation versions {got!r}"

    # Children before parent: the update drops all three; the live RestApi answers defaults.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(*args, with_children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    gr = ag.get_gateway_response(restApiId=api_id, responseType=_RESPONSE_TYPE)
    assert gr["defaultResponse"] is True, f"gateway response after the update: {gr!r}"
    parts = paginate(ag, "get_documentation_parts", "items", restApiId=api_id)
    versions = paginate(ag, "get_documentation_versions", "items", restApiId=api_id)
    assert (parts, versions) == ([], []), f"documentation after the update: {parts!r} {versions!r}"

    delete_stack(cfn, stack_id)
    code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    got = (code, masked(message, ctx.account))
    want = ("NotFoundException", f"Invalid API identifier specified <account>:{api_id}")
    assert got == want, f"GetRestApi after the stack delete: {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
