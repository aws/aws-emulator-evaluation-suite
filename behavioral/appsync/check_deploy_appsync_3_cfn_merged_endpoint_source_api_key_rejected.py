"""deploy-appsync-3-cfn-merged-endpoint-source-api-key-rejected."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appsync-3-cfn-merged-endpoint-source-api-key-rejected"
GROUP = "deploy-merged-api-source-association"
SERVICES = ["appsync"]

_TERMINAL_MERGE = ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED")




def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")


def _error_code(fn):
    """Return the AWS error code of a call that MUST fail. A success raises: it is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"call was expected to fail but succeeded: {result!r}")


def _post_json(ctx, url, headers, payload, timeout_s=30):
    """POST JSON with stdlib urllib -> (status, parsed_body). A 4xx/5xx is a RESULT."""
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(
        routed_url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers, **route_headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, {"transport_error": str(exc)}
    try:
        return status, (json.loads(raw) if raw else {})
    except ValueError:
        return status, {"raw": raw}


def _stack_failure_reasons(cfn, stack_name):
    reasons = []
    try:
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
            for ev in page["StackEvents"]:
                if ev.get("ResourceStatus", "").endswith("FAILED"):
                    reasons.append(
                        f"{ev['LogicalResourceId']}: {ev['ResourceStatus']}: "
                        f"{ev.get('ResourceStatusReason')}"
                    )
    except ClientError as exc:
        reasons.append(f"<describe_stack_events failed: {exc}>")
    return reasons[:8]


def _wait_stack(cfn, stack_name, *, want, timeout_s=780):
    """Poll a stack to a non-IN_PROGRESS status and assert it is ``want``."""
    stack = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, interval_s=10,
        description=f"stack {stack_name} leaving *_IN_PROGRESS",
    )
    assert stack["StackStatus"] == want, (
        f"stack {stack_name} ended {stack['StackStatus']!r}, expected {want!r}; "
        f"failures: {_stack_failure_reasons(cfn, stack_name)!r}"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _stack_status(cfn, stack_name):
    """Stack status by name; a stack name that no longer resolves is reported as DELETE_COMPLETE."""
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in exc.response["Error"].get("Message", ""):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(ctx, stack_name):
    """Teardown: delete and wait. A failure or timeout raises."""
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            except ClientError:
                return
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise RuntimeError(f"stack {stack_name} DELETE_FAILED: "
                                   f"{_stack_failure_reasons(cfn, stack_name)!r}")
            time.sleep(10)
        raise RuntimeError(f"stack {stack_name} still deleting after 600s")
    except Exception as exc:  # noqa: BLE001 - teardown must never mask the verdict
        raise RuntimeError(f"stack {stack_name} delete raised {exc!r}") from exc


def _undefined(field):
    return (f"Validation error of type FieldUndefined: Field '{field}' in type 'Query' "
            f"is undefined @ '{field}'")


def _js_literal(value):
    return (
        "export function request(ctx) {\n"
        f"  return {{ payload: '{value}' }};\n"
        "}\n"
        "export function response(ctx) {\n"
        "  return ctx.result;\n"
        "}\n"
    )


def _template(prefix, merge_type, literals, *, grant_source_graphql=True, source_key=False,
              associate=True, bad_association=False):
    """Source API + MERGED API (+ SourceApiAssociation) in ONE stack.

    ``literals`` maps Query field name -> the literal its NONE-backed JS resolver returns.
    ``grant_source_graphql=False`` drops appsync:SourceGraphQL from the merged API's execution
    role; ``bad_association=True`` adds a plain GRAPHQL API and an association that names it as
    the MERGED side.
    """
    sdl = "type Query {\n" + "".join(f"  {f}: String\n" for f in literals) + "}\n"
    api = {"Fn::GetAtt": ["SourceApi", "ApiId"]}
    statements = [
        {"Effect": "Allow", "Action": "appsync:StartSchemaMerge",
         "Resource": {"Fn::Sub": "arn:${AWS::Partition}:appsync:${AWS::Region}:"
                      "${AWS::AccountId}:apis/*/sourceApiAssociations/*"}},
    ]
    if grant_source_graphql:
        statements.insert(0, {
            "Effect": "Allow", "Action": "appsync:SourceGraphQL",
            "Resource": [{"Fn::GetAtt": ["SourceApi", "Arn"]},
                         {"Fn::Sub": "${SourceApi.Arn}/*"}],
        })
    resources = {
        "SourceApi": {
            "Type": "AWS::AppSync::GraphQLApi",
            "Properties": {
                "Name": f"{prefix}-src", "AuthenticationType": "API_KEY",
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            },
        },
        "SourceSchema": {
            "Type": "AWS::AppSync::GraphQLSchema",
            "Properties": {"ApiId": api, "Definition": sdl},
        },
        "NoneSource": {
            "Type": "AWS::AppSync::DataSource",
            "Properties": {"ApiId": api, "Name": "NoneSource", "Type": "NONE"},
        },
        "MergedRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow",
                                   "Principal": {"Service": "appsync.amazonaws.com"},
                                   "Action": "sts:AssumeRole"}],
                },
                "Policies": [{
                    "PolicyName": "merged-api-execution",
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
                }],
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            },
        },
        "MergedApi": {
            "Type": "AWS::AppSync::GraphQLApi",
            "Properties": {
                "Name": f"{prefix}-merged", "AuthenticationType": "API_KEY",
                "ApiType": "MERGED",
                "MergedApiExecutionRoleArn": {"Fn::GetAtt": ["MergedRole", "Arn"]},
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            },
        },
        "MergedKey": {
            "Type": "AWS::AppSync::ApiKey",
            "Properties": {"ApiId": {"Fn::GetAtt": ["MergedApi", "ApiId"]}},
        },
    }
    outputs = {
        "SourceApiId": {"Value": api},
        "SourceUrl": {"Value": {"Fn::GetAtt": ["SourceApi", "GraphQLUrl"]}},
        "MergedApiId": {"Value": {"Fn::GetAtt": ["MergedApi", "ApiId"]}},
        "MergedUrl": {"Value": {"Fn::GetAtt": ["MergedApi", "GraphQLUrl"]}},
        "MergedKey": {"Value": {"Fn::GetAtt": ["MergedKey", "ApiKey"]}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["MergedRole", "Arn"]}},
    }
    if source_key:
        resources["SourceKey"] = {"Type": "AWS::AppSync::ApiKey", "Properties": {"ApiId": api}}
        outputs["SourceKey"] = {"Value": {"Fn::GetAtt": ["SourceKey", "ApiKey"]}}
    depends = ["SourceSchema"]
    for i, (field, literal) in enumerate(literals.items()):
        logical = f"Resolver{i}"
        resources[logical] = {
            "Type": "AWS::AppSync::Resolver",
            "DependsOn": ["SourceSchema"],
            "Properties": {
                "ApiId": api, "TypeName": "Query", "FieldName": field, "Kind": "UNIT",
                "DataSourceName": {"Fn::GetAtt": ["NoneSource", "Name"]},
                "Runtime": {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"},
                "Code": _js_literal(literal),
            },
        }
        depends.append(logical)
    if associate:
        resources["Association"] = {
            "Type": "AWS::AppSync::SourceApiAssociation",
            "DependsOn": depends,
            "Properties": {
                "SourceApiIdentifier": api,
                "MergedApiIdentifier": {"Fn::GetAtt": ["MergedApi", "ApiId"]},
                "Description": "sim2real merged-api association",
                "SourceApiAssociationConfig": {"MergeType": merge_type},
            },
        }
        outputs["AssociationId"] = {"Value": {"Fn::GetAtt": ["Association", "AssociationId"]}}
    if bad_association:
        resources["PlainApi"] = {
            "Type": "AWS::AppSync::GraphQLApi",
            "Properties": {
                "Name": f"{prefix}-plain", "AuthenticationType": "API_KEY",
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            },
        }
        resources["BadAssociation"] = {
            "Type": "AWS::AppSync::SourceApiAssociation",
            "DependsOn": depends,
            "Properties": {
                "SourceApiIdentifier": api,
                "MergedApiIdentifier": {"Fn::GetAtt": ["PlainApi", "ApiId"]},
                "Description": "sim2real association naming a non-merged API",
                "SourceApiAssociationConfig": {"MergeType": merge_type},
            },
        }
        outputs["PlainApiId"] = {"Value": {"Fn::GetAtt": ["PlainApi", "ApiId"]}}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
            "Outputs": outputs}


def _settled_association(svc, merged_id, association_id, *, after=None):
    """Poll GetSourceApiAssociation to a terminal merge status (newer than ``after`` if given)."""
    def probe():
        return svc.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id
        )["sourceApiAssociation"]

    def done(a):
        if a["sourceApiAssociationStatus"] not in _TERMINAL_MERGE:
            return False
        if after is None or a["sourceApiAssociationStatus"] != "MERGE_SUCCESS":
            return True
        return a.get("lastSuccessfulMergeDate") is not None and a["lastSuccessfulMergeDate"] > after

    return _poll_until(probe, done, timeout_s=300, interval_s=5,
                       description=f"association {association_id} reaching a terminal merge")




@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """API keys do not cross the merge boundary: the MERGED endpoint rejects the SOURCE API's key
    with 401 UnauthorizedException and vice versa, while each key works on its own endpoint.
    """
    cfn = ctx.client("cloudformation")
    svc = ctx.client("appsync")
    stack = ctx.unique_name("sim2real-appsync3-keys-")
    first_literal = ctx.unique_name("first-")

    cfn.create_stack(
        StackName=stack,
        TemplateBody=json.dumps(_template(stack, "AUTO_MERGE", {"greeting": first_literal},
                                          source_key=True)),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack))
    out = _wait_stack(cfn, stack, want="CREATE_COMPLETE")
    merged_url, source_url = out["MergedUrl"], out["SourceUrl"]
    merged_key, source_key = out["MergedKey"], out["SourceKey"]
    assert merged_key != source_key, "the stack minted the same key for both APIs"

    settled = _settled_association(svc, out["MergedApiId"], out["AssociationId"])
    assert settled["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"merge ended {settled['sourceApiAssociationStatus']!r} "
        f"detail={settled.get('sourceApiAssociationStatusDetail')!r}"
    )

    query = {"query": "query { greeting }"}
    # Positive controls: each key on its own endpoint resolves the field.
    status, body = _poll_until(
        lambda: _post_json(ctx, merged_url, {"x-api-key": merged_key}, query),
        lambda r: r[0] == 200 and not (r[1] or {}).get("errors"),
        timeout_s=180, interval_s=5, description="the merged endpoint with the merged key",
    )
    assert body["data"]["greeting"] == first_literal, f"merged endpoint returned {body!r}"
    status, body = _post_json(ctx, source_url, {"x-api-key": source_key}, query)
    assert status == 200 and body.get("data") == {"greeting": first_literal}, (
        f"source endpoint with its own key returned {status!r} {body!r}"
    )

    for url, key, what in ((merged_url, source_key, "source key on the MERGED endpoint"),
                           (source_url, merged_key, "merged key on the SOURCE endpoint")):
        status, body = _post_json(ctx, url, {"x-api-key": key}, query)
        assert status == 401, f"{what} was not rejected: {status!r} {body!r}"
        assert "data" not in body or body.get("data") is None, (
            f"{what} was rejected but still leaked data: {body!r}"
        )
        errors = body.get("errors") or []
        assert errors and errors[0].get("errorType") == "UnauthorizedException", (
            f"{what} rejected with {body!r}, expected errorType UnauthorizedException"
        )

    # The rejected requests changed nothing: the merged key still works afterwards.
    status, body = _post_json(ctx, merged_url, {"x-api-key": merged_key}, query)
    assert status == 200 and body.get("data") == {"greeting": first_literal}, (
        f"merged endpoint stopped answering its own key: {status!r} {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
