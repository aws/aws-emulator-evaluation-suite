"""deploy-appsync-3-cfn-merged-api-manual-merge-withholds-update-until-merge."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appsync-3-cfn-merged-api-manual-merge-withholds-update-until-merge"
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
    "axis:happy-path",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A MANUAL_MERGE SourceApiAssociation merges once at association time, then withholds later
    source changes: a field added by update_stack is served by the SOURCE endpoint at once, and by
    the MERGED endpoint only after StartSchemaMerge is polled to SUCCESS.
    """
    cfn = ctx.client("cloudformation")
    svc = ctx.client("appsync")
    stack = ctx.unique_name("sim2real-appsync3-manual-")
    first_literal = ctx.unique_name("first-")
    second_literal = ctx.unique_name("second-")

    cfn.create_stack(
        StackName=stack,
        TemplateBody=json.dumps(_template(stack, "MANUAL_MERGE", {"greeting": first_literal},
                                          source_key=True)),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack))
    out = _wait_stack(cfn, stack, want="CREATE_COMPLETE")
    merged_id, association_id = out["MergedApiId"], out["AssociationId"]
    merged_url, source_url = out["MergedUrl"], out["SourceUrl"]
    merged_h, source_h = {"x-api-key": out["MergedKey"]}, {"x-api-key": out["SourceKey"]}

    # Creating the association performs the INITIAL merge even under MANUAL_MERGE;
    # only later source changes wait for StartSchemaMerge.
    first = _settled_association(svc, merged_id, association_id)
    assert first["sourceApiAssociationConfig"]["mergeType"] == "MANUAL_MERGE", (
        f"association config is {first['sourceApiAssociationConfig']!r}"
    )
    assert first["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"association-time merge ended {first['sourceApiAssociationStatus']!r} "
        f"detail={first.get('sourceApiAssociationStatusDetail')!r}"
    )
    first_merge_date = first["lastSuccessfulMergeDate"]
    assert first_merge_date is not None, f"no lastSuccessfulMergeDate after the merge: {first!r}"
    status, body = _poll_until(
        lambda: _post_json(ctx, merged_url, merged_h, {"query": "query { greeting }"}),
        lambda r: r[0] == 200 and not (r[1] or {}).get("errors"),
        timeout_s=180, interval_s=5, description="the merged endpoint serving greeting",
    )
    assert body["data"]["greeting"] == first_literal, f"merged endpoint returned {body!r}"

    cfn.update_stack(
        StackName=stack,
        TemplateBody=json.dumps(_template(
            stack, "MANUAL_MERGE", {"greeting": first_literal, "second": second_literal},
            source_key=True)),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    _wait_stack(cfn, stack, want="UPDATE_COMPLETE")

    # Barrier: the SOURCE endpoint serves the new field, so the change has landed upstream.
    status, body = _poll_until(
        lambda: _post_json(ctx, source_url, source_h, {"query": "query { second }"}),
        lambda r: r[0] == 200 and not (r[1] or {}).get("errors"),
        timeout_s=180, interval_s=5, description="the source endpoint serving the new field",
    )
    assert body["data"]["second"] == second_literal, f"source endpoint returned {body!r}"

    status, body = _post_json(ctx, merged_url, merged_h, {"query": "query { second }"})
    assert status == 200 and body.get("data") is None and body.get("errors"), (
        f"MANUAL_MERGE leaked an unmerged source change to the merged endpoint: "
        f"{status!r} {body!r}"
    )
    assert body["errors"][0]["message"] == _undefined("second"), (
        f"unmerged-field query error was {body['errors']!r}"
    )
    held = svc.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=association_id)["sourceApiAssociation"]
    assert held["lastSuccessfulMergeDate"] == first_merge_date, (
        f"a merge ran without StartSchemaMerge: {first_merge_date!r} -> "
        f"{held['lastSuccessfulMergeDate']!r} status={held['sourceApiAssociationStatus']!r}"
    )

    merge = svc.start_schema_merge(associationId=association_id, mergedApiIdentifier=merged_id)
    assert merge["sourceApiAssociationStatus"] in ("MERGE_SCHEDULED", "MERGE_IN_PROGRESS"), (
        f"StartSchemaMerge returned status {merge!r}"
    )
    after = _settled_association(svc, merged_id, association_id, after=first_merge_date)
    assert after["sourceApiAssociationStatus"] == "MERGE_SUCCESS", (
        f"second manual merge ended {after['sourceApiAssociationStatus']!r} "
        f"detail={after.get('sourceApiAssociationStatusDetail')!r}"
    )
    status, body = _poll_until(
        lambda: _post_json(ctx, merged_url, merged_h, {"query": "query { greeting second }"}),
        lambda r: r[0] == 200 and not (r[1] or {}).get("errors"),
        timeout_s=180, interval_s=5,
        description="the merged endpoint serving the manually merged field",
    )
    assert body["data"] == {"greeting": first_literal, "second": second_literal}, (
        f"merged endpoint after manual merge returned {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
