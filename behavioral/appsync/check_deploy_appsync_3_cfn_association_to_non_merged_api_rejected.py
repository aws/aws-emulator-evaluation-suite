"""deploy-appsync-3-cfn-association-to-non-merged-api-rejected."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appsync-3-cfn-association-to-non-merged-api-rejected"
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
    "concern:deploy",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:endpoint",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An update_stack adding a SourceApiAssociation naming a plain GRAPHQL API as merged API
    rolls back; the existing merged association stays MERGE_SUCCESS, the only association, and the
    merged endpoint still serves the source field.
    """
    cfn = ctx.client("cloudformation")
    svc = ctx.client("appsync")
    stack = ctx.unique_name("sim2real-appsync3-bad-")
    first_literal = ctx.unique_name("first-")

    cfn.create_stack(
        StackName=stack,
        TemplateBody=json.dumps(_template(stack, "AUTO_MERGE", {"greeting": first_literal})),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack))
    out = _wait_stack(cfn, stack, want="CREATE_COMPLETE")
    merged_id, association_id, merged_url = (
        out["MergedApiId"], out["AssociationId"], out["MergedUrl"]
    )
    merged_h = {"x-api-key": out["MergedKey"]}
    first = _settled_association(svc, merged_id, association_id)
    assert first["sourceApiAssociationStatus"] == "MERGE_SUCCESS", f"merge ended {first!r}"

    cfn.update_stack(
        StackName=stack,
        TemplateBody=json.dumps(_template(stack, "AUTO_MERGE", {"greeting": first_literal},
                                          bad_association=True)),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    out2 = _wait_stack(cfn, stack, want="UPDATE_ROLLBACK_COMPLETE")
    assert out2.get("AssociationId") == association_id and "PlainApiId" not in out2, (
        f"the rolled-back stack's outputs changed: {out2!r}"
    )

    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        events.extend(page["StackEvents"])
    failed = [e for e in events
              if e["LogicalResourceId"] == "BadAssociation" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(failed) == 1, f"expected one BadAssociation CREATE_FAILED event: {failed!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    handler = re.search(r"HandlerErrorCode: (\w+)", reason)
    assert handler and handler.group(1) == "InvalidRequest", (
        f"BadAssociation failed with {reason!r}, expected HandlerErrorCode InvalidRequest"
    )
    plain = [e for e in events
             if e["LogicalResourceId"] == "PlainApi" and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert len(plain) == 1, f"the plain GRAPHQL API was never created: {plain!r}"
    plain_id = plain[0]["PhysicalResourceId"].rsplit("/", 1)[-1]
    assert f"expected api to be type MERGED for api : {plain_id}" in reason, (
        f"the rejection does not name the non-merged API {plain_id!r}: {reason!r}"
    )

    # Effect absent: the plain API the update created was rolled back.
    code = _error_code(lambda: svc.get_graphql_api(apiId=plain_id))
    assert code == "NotFoundException", f"GetGraphqlApi(plain) after rollback: {code!r}"

    # Positive control: the existing association and the merged endpoint are untouched.
    listed = []
    for page in svc.get_paginator("list_source_api_associations").paginate(apiId=merged_id):
        listed.extend(page["sourceApiAssociationSummaries"])
    assert [a["associationId"] for a in listed] == [association_id], (
        f"merged API associations after the failed update: {listed!r}"
    )
    still = svc.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=association_id)["sourceApiAssociation"]
    assert still["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"the good association left MERGE_SUCCESS: {still!r}"
    )
    status, body = _poll_until(
        lambda: _post_json(ctx, merged_url, merged_h, {"query": "query { greeting }"}),
        lambda r: r[0] == 200 and not (r[1] or {}).get("errors"),
        timeout_s=180, interval_s=5, description="the merged endpoint serving greeting",
    )
    assert body["data"] == {"greeting": first_literal}, (
        f"merged endpoint after the rolled-back update returned {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
