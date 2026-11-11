"""deploy-appsync-3-cfn-merged-api-auto-merge-serves-source-update."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appsync-3-cfn-merged-api-auto-merge-serves-source-update"
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
    """Return the AWS error code and message of a call that MUST fail. A success raises: it is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
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
    "axis:happy-path",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A CFN AUTO_MERGE SourceApiAssociation has the MERGED endpoint serve source resolvers;
    a source-only update_stack is merged and served, and stack deletion removes the association
    and both APIs.
    """
    cfn = ctx.client("cloudformation")
    svc = ctx.client("appsync")
    stack = ctx.unique_name("sim2real-appsync3-auto-")
    first_literal = ctx.unique_name("first-")
    second_literal = ctx.unique_name("second-")

    cfn.create_stack(
        StackName=stack,
        TemplateBody=json.dumps(_template(stack, "AUTO_MERGE", {"greeting": first_literal})),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack))
    out = _wait_stack(cfn, stack, want="CREATE_COMPLETE")
    merged_id, source_id = out["MergedApiId"], out["SourceApiId"]
    association_id, merged_url, merged_key = (
        out["AssociationId"], out["MergedUrl"], out["MergedKey"]
    )

    merged = svc.get_graphql_api(apiId=merged_id)["graphqlApi"]
    assert merged["apiType"] == "MERGED", f"merged API apiType is {merged.get('apiType')!r}"
    assert merged.get("mergedApiExecutionRoleArn") == out["RoleArn"], (
        f"merged API execution role {merged.get('mergedApiExecutionRoleArn')!r} is not the "
        f"stack's role {out['RoleArn']!r}"
    )
    assert merged["uris"]["GRAPHQL"] == merged_url, (
        f"GraphQLUrl output {merged_url!r} != GetGraphqlApi uri {merged['uris']['GRAPHQL']!r}"
    )

    first = _settled_association(svc, merged_id, association_id)
    assert first["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"initial AUTO_MERGE did not succeed: {first['sourceApiAssociationStatus']!r} "
        f"detail={first.get('sourceApiAssociationStatusDetail')!r}"
    )
    assert first["sourceApiAssociationConfig"]["mergeType"] == "AUTO_MERGE", (
        f"association mergeType is {first['sourceApiAssociationConfig']!r}"
    )
    assert first["sourceApiId"] == source_id and first["mergedApiId"] == merged_id, (
        f"association links {first['sourceApiId']!r}->{first['mergedApiId']!r}, "
        f"expected {source_id!r}->{merged_id!r}"
    )
    first_merge_date = first["lastSuccessfulMergeDate"]

    headers = {"x-api-key": merged_key}
    status, body = _poll_until(
        lambda: _post_json(ctx, merged_url, headers, {"query": "query { greeting }"}),
        lambda r: r[0] == 200 and not (r[1] or {}).get("errors"),
        timeout_s=180, interval_s=5,
        description="the merged endpoint resolving the source field",
    )
    assert body["data"]["greeting"] == first_literal, (
        f"merged endpoint returned {body!r}, expected the source resolver's {first_literal!r}"
    )

    status, body = _post_json(ctx, merged_url, headers, {"query": "query { second }"})
    assert status == 200 and body.get("data") is None and body.get("errors"), (
        f"merged endpoint accepted a field not yet in any source: {status!r} {body!r}"
    )
    assert body["errors"][0]["message"] == _undefined("second"), (
        f"unknown-field query error was {body['errors']!r}"
    )

    cfn.update_stack(
        StackName=stack,
        TemplateBody=json.dumps(_template(
            stack, "AUTO_MERGE", {"greeting": first_literal, "second": second_literal}
        )),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    out2 = _wait_stack(cfn, stack, want="UPDATE_COMPLETE")
    assert out2["MergedApiId"] == merged_id and out2["AssociationId"] == association_id, (
        f"the source-only update replaced the merged API or association: {out2!r}"
    )

    status, body = _poll_until(
        lambda: _post_json(ctx, merged_url, headers, {"query": "query { greeting second }"}),
        lambda r: r[0] == 200 and not (r[1] or {}).get("errors")
        and (r[1].get("data") or {}).get("second") == second_literal,
        timeout_s=300, interval_s=5,
        description="the merged endpoint serving the field added by update_stack",
    )
    assert body["data"] == {"greeting": first_literal, "second": second_literal}, (
        f"merged endpoint after update returned {body!r}"
    )
    after = _settled_association(svc, merged_id, association_id, after=first_merge_date)
    assert after["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"post-update auto merge ended {after['sourceApiAssociationStatus']!r} "
        f"detail={after.get('sourceApiAssociationStatusDetail')!r}"
    )
    assert after["lastSuccessfulMergeDate"] > first_merge_date, (
        f"lastSuccessfulMergeDate did not advance: {first_merge_date!r} -> "
        f"{after['lastSuccessfulMergeDate']!r}"
    )

    cfn.delete_stack(StackName=stack)
    gone = _poll_until(
        lambda: _stack_status(cfn, stack),
        lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=600, interval_s=10, description=f"stack {stack} deletion",
    )
    assert gone == "DELETE_COMPLETE", (
        f"stack ended {gone!r}: {_stack_failure_reasons(cfn, stack)!r}"
    )
    code, message = _error_code(lambda: svc.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=association_id))
    assert code == "NotFoundException", f"GetSourceApiAssociation after delete: {code!r}"
    assert message == "API not found.", (
        f"expected the exact NotFoundException message AWS returns, got {message!r}"
    )
    code, message = _error_code(lambda: svc.get_graphql_api(apiId=merged_id))
    assert code == "NotFoundException", f"GetGraphqlApi(merged) after delete: {code!r}"
    assert message == "API not found.", (
        f"expected the exact NotFoundException message AWS returns, got {message!r}"
    )
    code, message = _error_code(lambda: svc.get_graphql_api(apiId=source_id))
    assert code == "NotFoundException", f"GetGraphqlApi(source) after delete: {code!r}"
    assert message == "API not found.", (
        f"expected the exact NotFoundException message AWS returns, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
