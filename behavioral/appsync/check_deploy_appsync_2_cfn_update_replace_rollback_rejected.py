"""deploy-appsync-2-cfn-update-replace-rollback-rejected."""
from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "deploy-appsync-2-cfn-update-replace-rollback-rejected"
GROUP = "deploy-cfn-update-rollback"
SERVICES = ["appsync"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """CloudFormation updates an AppSync API in place, replaces a renamed data source, and
    rolls back a rejected resolver update and a rejected schema create without collateral.
    """
    appsync = ctx.client("appsync")
    cfn = ctx.client("cloudformation")

    stack_a = ctx.unique_name("sim2real-appsync2-a-")
    stack_b = ctx.unique_name("sim2real-appsync2-b-")
    api_name_a = ctx.unique_name("sim2real-appsync2-a-")
    api_name_b = ctx.unique_name("sim2real-appsync2-b-")
    params_a = [{"ParameterKey": "ApiName", "ParameterValue": api_name_a}]
    params_b = [{"ParameterKey": "ApiName", "ParameterValue": api_name_b}]
    stack_tags = [{"Key": "sim2real", "Value": CHECK}]

    # Both creates are issued up front so the two stacks provision concurrently.
    cfn.create_stack(StackName=stack_a, TemplateBody=json.dumps(_template_a(1)),
                     Parameters=params_a, Tags=stack_tags)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_a))
    cfn.create_stack(StackName=stack_b, TemplateBody=json.dumps(_template_b()),
                     Parameters=params_b, Tags=stack_tags, OnFailure="ROLLBACK")
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_b))

    # ---------------- Stack A, v1 ----------------
    status_a = _wait_terminal(ctx, cfn, stack_a)
    assert status_a == "CREATE_COMPLETE", (
        f"stack A v1 ended {status_a!r}, expected CREATE_COMPLETE; "
        f"failures: {_failure_events(cfn, stack_a)!r}"
    )
    out = _outputs(cfn, stack_a)
    api_id, url, key = out["ApiId"], out["GraphQLUrl"], out["ApiKeyValue"]
    api_phys_v1 = _physical_id(cfn, stack_a, "GraphQLApi")
    ds_phys_v1 = _physical_id(cfn, stack_a, "NoneDataSource")

    probe = ctx.unique_name("v1-")
    status, body = _graphql(ctx, url, key, "query Q($m: String) { echo(msg: $m) { msg } }", {"m": probe})
    assert status == 200 and not body.get("errors"), f"v1 query failed: HTTP {status} {body!r}"
    assert body["data"]["echo"]["msg"] == probe, f"v1 echo returned {body['data']!r}, expected msg={probe!r}"
    # The v2 field must not exist yet: the endpoint rejects the selection at validation.
    status, body = _graphql(ctx, url, key, "query { echo(msg: \"x\") { msg version } }")
    errs = body.get("errors") or []
    assert errs and any("version" in (e.get("message") or "") for e in errs), (
        f"v1 schema accepted the not-yet-declared field 'version': HTTP {status} {body!r}"
    )
    assert not body.get("data"), f"v1 rejected selection still returned data: {body!r}"

    # ---------------- Stack A, change set v2 (in-place) ----------------
    changes_v2 = _change_set(ctx, cfn, stack_a, _template_a(2), params_a, ctx.unique_name("v2-"))
    by_id_v2 = {c["LogicalResourceId"]: c for c in changes_v2}
    assert set(by_id_v2) == {"GraphQLSchema", "EchoResolver"}, (
        f"v2 change set touched {sorted(by_id_v2)!r}, expected exactly GraphQLSchema + EchoResolver; "
        f"changes: {changes_v2!r}"
    )
    # The CloudFormation reference documents both AWS::AppSync::Resolver Code and
    # AWS::AppSync::GraphQLSchema Definition as 'Update requires: No interruption', which a change
    # set reports as RequiresRecreation 'Never' and Replacement 'False'. Execution then confirms it
    # by the unchanged physical ids asserted below.
    expected_v2 = {"EchoResolver": ("Code", "Never", "False"),
                   "GraphQLSchema": ("Definition", "Never", "False")}
    for lid, (prop, recreation, replacement) in expected_v2.items():
        rc = by_id_v2[lid]
        assert rc["Action"] == "Modify", f"v2 {lid} action {rc['Action']!r}, expected 'Modify'"
        targets = {(d["Target"].get("Name"), d["Target"].get("RequiresRecreation")) for d in rc.get("Details", [])}
        assert targets == {(prop, recreation)}, (
            f"v2 {lid} change details {targets!r}, expected only {prop!r} with RequiresRecreation {recreation!r}"
        )
        assert rc.get("Replacement") == replacement, (
            f"v2 {lid} Replacement {rc.get('Replacement')!r}, expected {replacement!r}"
        )
    schema_phys_v1 = _physical_id(cfn, stack_a, "GraphQLSchema")
    resolver_phys_v1 = _physical_id(cfn, stack_a, "EchoResolver")
    _execute(ctx, cfn, stack_a, changes_v2.change_set_name)
    status_a = _wait_terminal(ctx, cfn, stack_a)
    assert status_a == "UPDATE_COMPLETE", (
        f"stack A v2 ended {status_a!r}, expected UPDATE_COMPLETE; failures: {_failure_events(cfn, stack_a)!r}"
    )
    for lid, before in (("GraphQLSchema", schema_phys_v1), ("EchoResolver", resolver_phys_v1)):
        after = _physical_id(cfn, stack_a, lid)
        assert after == before, f"v2 replaced {lid}: physical id {before!r} -> {after!r}, expected in-place"
    api_phys_v2 = _physical_id(cfn, stack_a, "GraphQLApi")
    assert api_phys_v2 == api_phys_v1, (
        f"GraphQLApi physical id changed on an in-place update: {api_phys_v1!r} -> {api_phys_v2!r}"
    )
    assert _outputs(cfn, stack_a)["ApiId"] == api_id, "ApiId output changed on an in-place update"
    probe = ctx.unique_name("v2-")
    status, body = _graphql(ctx, url, key, "query Q($m: String) { echo(msg: $m) { msg version } }", {"m": probe})
    assert status == 200 and not body.get("errors"), f"v2 query failed: HTTP {status} {body!r}"
    assert body["data"]["echo"] == {"msg": probe, "version": "v2"}, (
        f"v2 echo returned {body['data']['echo']!r}, expected the new resolver code's {{msg, version:'v2'}}"
    )

    # ---------------- Stack A, change set v3 (DataSource Name -> replacement) ----------------
    changes_v3 = _change_set(ctx, cfn, stack_a, _template_a(3), params_a, ctx.unique_name("v3-"))
    by_id_v3 = {c["LogicalResourceId"]: c for c in changes_v3}
    assert "NoneDataSource" in by_id_v3, f"v3 change set has no NoneDataSource change: {changes_v3!r}"
    ds_rc = by_id_v3["NoneDataSource"]
    assert ds_rc["Action"] == "Modify" and ds_rc.get("Replacement") == "True", (
        f"v3 NoneDataSource change {ds_rc!r}, expected Action Modify with Replacement 'True'"
    )
    assert "GraphQLApi" not in by_id_v3, f"v3 change set touches GraphQLApi: {by_id_v3['GraphQLApi']!r}"
    _execute(ctx, cfn, stack_a, changes_v3.change_set_name)
    status_a = _wait_terminal(ctx, cfn, stack_a)
    assert status_a == "UPDATE_COMPLETE", (
        f"stack A v3 ended {status_a!r}, expected UPDATE_COMPLETE; failures: {_failure_events(cfn, stack_a)!r}"
    )
    ds_phys_v3 = _physical_id(cfn, stack_a, "NoneDataSource")
    assert ds_phys_v3 != ds_phys_v1, f"DataSource replaced but physical id unchanged: {ds_phys_v3!r}"
    assert _physical_id(cfn, stack_a, "GraphQLApi") == api_phys_v1, "GraphQLApi physical id changed in v3"
    names = {d["name"] for d in _list_data_sources(appsync, api_id)}
    assert names == {"NoneDSRenamed"}, (
        f"after replacement the API holds data sources {sorted(names)!r}, expected only the new 'NoneDSRenamed'"
    )
    resolver = appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert resolver["dataSourceName"] == "NoneDSRenamed", (
        f"resolver still bound to {resolver['dataSourceName']!r} after the data source was replaced"
    )
    probe = ctx.unique_name("v3-")
    status, body = _graphql(ctx, url, key, "query Q($m: String) { echo(msg: $m) { msg version } }", {"m": probe})
    assert status == 200 and not body.get("errors"), f"v3 query failed: HTTP {status} {body!r}"
    assert body["data"]["echo"] == {"msg": probe, "version": "v2"}, f"v3 echo returned {body['data']!r}"

    # ---------------- Stack A, update_stack v4 (rejected resolver -> rollback) ----------------
    cfn.update_stack(StackName=stack_a, TemplateBody=json.dumps(_template_a(4)), Parameters=params_a)
    status_a = _wait_terminal(ctx, cfn, stack_a)
    assert status_a == "UPDATE_ROLLBACK_COMPLETE", (
        f"stack A v4 ended {status_a!r}, expected UPDATE_ROLLBACK_COMPLETE for a resolver on an absent field"
    )
    failed = _failure_events(cfn, stack_a)
    failed_ids = {e["LogicalResourceId"] for e in failed}
    assert failed_ids == {"GhostResolver"}, (
        f"v4 resource failures were on {sorted(failed_ids)!r}, expected exactly the GhostResolver; events: {failed!r}"
    )
    assert all(e["ResourceStatus"] == "CREATE_FAILED" for e in failed), (
        f"v4 GhostResolver failure status was {[e['ResourceStatus'] for e in failed]!r}, expected CREATE_FAILED"
    )
    ghost_code = _error_code(lambda: appsync.get_resolver(apiId=api_id, typeName="Query", fieldName="ghost"))
    assert ghost_code == "NotFoundException", (
        f"GetResolver(Query.ghost) after rollback returned {ghost_code!r}, expected NotFoundException"
    )
    assert _physical_id(cfn, stack_a, "GraphQLApi") == api_phys_v1, "GraphQLApi physical id changed by rollback"
    probe = ctx.unique_name("v4-")
    status, body = _graphql(ctx, url, key, "query Q($m: String) { echo(msg: $m) { msg version } }", {"m": probe})
    assert status == 200 and not body.get("errors"), f"post-rollback query failed: HTTP {status} {body!r}"
    assert body["data"]["echo"] == {"msg": probe, "version": "v2"}, (
        f"after rollback echo returned {body['data']!r}; the v3 generation must still serve"
    )

    # ---------------- Stack B (fresh create, invalid SDL -> rollback) ----------------
    status_b = _wait_terminal(ctx, cfn, stack_b)
    assert status_b == "ROLLBACK_COMPLETE", (
        f"stack B ended {status_b!r}, expected ROLLBACK_COMPLETE for an SDL referencing an undefined type"
    )
    events_b = _all_events(cfn, stack_b)
    failed_b = [e for e in events_b if e["ResourceStatus"].endswith("_FAILED")
                and e["LogicalResourceId"] != stack_b]
    assert {e["LogicalResourceId"] for e in failed_b} == {"GraphQLSchema"}, (
        f"stack B failures on {sorted({e['LogicalResourceId'] for e in failed_b})!r}, expected only GraphQLSchema; "
        f"events: {failed_b!r}"
    )
    reason = failed_b[0].get("ResourceStatusReason") or ""
    assert failed_b[0]["ResourceStatus"] == "CREATE_FAILED", f"schema failure status {failed_b[0]!r}"
    # The resource handler waits for the schema creation to succeed and reports NotStabilized
    # when it fails; AppSync's own GetSchemaCreationStatus carries the SDL error.
    assert "AWS::AppSync::GraphQLSchema" in reason and "HandlerErrorCode: NotStabilized" in reason, (
        f"schema failure reason is not the GraphQLSchema handler's NotStabilized: {reason!r}"
    )
    # The same SDL on a scratch API ties the Schema's failure to that SDL's undefined type.
    sdl_status, sdl_details = _direct_schema_creation(ctx, appsync, _SDL_PHANTOM)
    assert sdl_status == "FAILED", (
        f"GetSchemaCreationStatus for the stack B SDL ended {sdl_status!r} ({sdl_details!r}), expected FAILED"
    )
    assert "PhantomType" in (sdl_details or ""), (
        f"GetSchemaCreationStatus details for the stack B SDL do not name the undefined type: {sdl_details!r}"
    )
    for lid in ("GraphQLApi", "ApiKey"):
        seq = [e["ResourceStatus"] for e in reversed(events_b) if e["LogicalResourceId"] == lid]
        assert "CREATE_COMPLETE" in seq and seq[-1] == "DELETE_COMPLETE", (
            f"stack B {lid} status sequence {seq!r}; expected it created and then deleted by the rollback"
        )
    api_arn_b = next(e["PhysicalResourceId"] for e in events_b
                     if e["LogicalResourceId"] == "GraphQLApi" and e["ResourceStatus"] == "CREATE_COMPLETE")
    api_id_b = _api_id_from_arn(api_arn_b)
    code_b = _error_code(lambda: appsync.get_graphql_api(apiId=api_id_b))
    assert code_b == "NotFoundException", (
        f"GetGraphqlApi on rolled-back API {api_id_b!r} returned {code_b!r}, expected NotFoundException"
    )

    # ---------------- Teardown of A, asserted by a NotFound read ----------------
    cfn.delete_stack(StackName=stack_a)
    status_a = _wait_terminal(ctx, cfn, stack_a)
    assert status_a == "DELETE_COMPLETE", f"stack A delete ended {status_a!r}, expected DELETE_COMPLETE"
    code_a = _error_code(lambda: appsync.get_graphql_api(apiId=api_id))
    assert code_a == "NotFoundException", (
        f"GetGraphqlApi on deleted stack A's API {api_id!r} returned {code_a!r}, expected NotFoundException"
    )


_SDL_V1 = "type Echo {\n  msg: String\n}\ntype Query {\n  echo(msg: String): Echo\n}\nschema {\n  query: Query\n}\n"
_SDL_V2 = (
    "type Echo {\n  msg: String\n  version: String\n}\ntype Query {\n  echo(msg: String): Echo\n}\n"
    "schema {\n  query: Query\n}\n"
)
_CODE_V1 = (
    "export function request(ctx) {\n  return {};\n}\n"
    "export function response(ctx) {\n  return { msg: ctx.args.msg };\n}\n"
)
_CODE_V2 = (
    "export function request(ctx) {\n  return {};\n}\n"
    "export function response(ctx) {\n  return { msg: ctx.args.msg, version: 'v2' };\n}\n"
)
_SDL_PHANTOM = "type Query {\n  item: PhantomType\n}\nschema {\n  query: Query\n}\n"
_JS = {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"}


def _template_a(version: int) -> dict:
    api = {"Fn::GetAtt": ["GraphQLApi", "ApiId"]}
    resources = {
        "GraphQLApi": {"Type": "AWS::AppSync::GraphQLApi",
                       "Properties": {"Name": {"Ref": "ApiName"}, "AuthenticationType": "API_KEY"}},
        "ApiKey": {"Type": "AWS::AppSync::ApiKey", "Properties": {"ApiId": api}},
        "GraphQLSchema": {"Type": "AWS::AppSync::GraphQLSchema",
                          "Properties": {"ApiId": api, "Definition": _SDL_V1 if version == 1 else _SDL_V2}},
        "NoneDataSource": {"Type": "AWS::AppSync::DataSource",
                           "Properties": {"ApiId": api, "Type": "NONE",
                                          "Name": "NoneDS" if version <= 2 else "NoneDSRenamed"}},
        "EchoResolver": {"Type": "AWS::AppSync::Resolver", "DependsOn": ["GraphQLSchema"],
                         "Properties": {"ApiId": api, "TypeName": "Query", "FieldName": "echo",
                                        "DataSourceName": {"Fn::GetAtt": ["NoneDataSource", "Name"]},
                                        "Kind": "UNIT", "Runtime": _JS,
                                        "Code": _CODE_V1 if version == 1 else _CODE_V2}},
    }
    if version == 4:
        resources["GhostResolver"] = {
            "Type": "AWS::AppSync::Resolver", "DependsOn": ["GraphQLSchema"],
            "Properties": {"ApiId": api, "TypeName": "Query", "FieldName": "ghost",
                           "DataSourceName": {"Fn::GetAtt": ["NoneDataSource", "Name"]},
                           "Kind": "UNIT", "Runtime": _JS, "Code": _CODE_V2},
        }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ApiName": {"Type": "String"}},
        "Resources": resources,
        "Outputs": {
            "ApiId": {"Value": api},
            "GraphQLUrl": {"Value": {"Fn::GetAtt": ["GraphQLApi", "GraphQLUrl"]}},
            "ApiKeyValue": {"Value": {"Fn::GetAtt": ["ApiKey", "ApiKey"]}},
        },
    }


def _template_b() -> dict:
    api = {"Fn::GetAtt": ["GraphQLApi", "ApiId"]}
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ApiName": {"Type": "String"}},
        "Resources": {
            "GraphQLApi": {"Type": "AWS::AppSync::GraphQLApi",
                           "Properties": {"Name": {"Ref": "ApiName"}, "AuthenticationType": "API_KEY"}},
            "ApiKey": {"Type": "AWS::AppSync::ApiKey", "Properties": {"ApiId": api}},
            # Syntactically valid SDL whose Query field returns a type that is never declared.
            # DependsOn ApiKey so the key exists before the schema fails and the rollback must remove it.
            "GraphQLSchema": {"Type": "AWS::AppSync::GraphQLSchema", "DependsOn": ["ApiKey"],
                              "Properties": {"ApiId": api, "Definition": _SDL_PHANTOM}},
        },
    }


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


class _Changes(list):
    change_set_name = ""


def _change_set(ctx, cfn, stack: str, template: dict, params: list, name: str) -> _Changes:
    cs_name = "sim2real-" + "".join(ch if ch.isalnum() else "-" for ch in name)
    cfn.create_change_set(StackName=stack, ChangeSetName=cs_name, ChangeSetType="UPDATE",
                          TemplateBody=json.dumps(template), Parameters=params)
    deadline = time.time() + _budget_s(ctx, 300)
    while True:
        d = cfn.describe_change_set(StackName=stack, ChangeSetName=cs_name)
        if d["Status"] in ("CREATE_COMPLETE", "FAILED"):
            break
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"change set {cs_name} finishing creation: the run budget ended "
                               "first; not graded")
        assert time.time() < deadline, f"change set {cs_name} stuck in {d['Status']!r}"
        time.sleep(1)
    assert d["Status"] == "CREATE_COMPLETE", f"change set {cs_name} {d['Status']!r}: {d.get('StatusReason')!r}"
    changes = _Changes()
    token = None
    while True:
        changes.extend(c["ResourceChange"] for c in d["Changes"] if c.get("Type") == "Resource")
        token = d.get("NextToken")
        if not token:
            break
        d = cfn.describe_change_set(StackName=stack, ChangeSetName=cs_name, NextToken=token)
    changes.change_set_name = cs_name
    return changes


def _execute(ctx, cfn, stack: str, cs_name: str) -> None:
    deadline = time.time() + _budget_s(ctx, 120)
    while True:
        d = cfn.describe_change_set(StackName=stack, ChangeSetName=cs_name)
        if d.get("ExecutionStatus") == "AVAILABLE":
            break
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"change set {cs_name} becoming AVAILABLE: the run budget ended "
                               "first; not graded")
        assert time.time() < deadline, f"change set {cs_name} never AVAILABLE: {d.get('ExecutionStatus')!r}"
        time.sleep(1)
    cfn.execute_change_set(StackName=stack, ChangeSetName=cs_name)
    # Wait until the execution has started: the stack left its terminal status, or the change set
    # is no longer AVAILABLE (a fast execution can already have reached a terminal stack status).
    deadline = time.time() + _budget_s(ctx, 120)
    while cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"] in _TERMINAL:
        try:
            cs = cfn.describe_change_set(StackName=stack, ChangeSetName=cs_name)
        except cfn.exceptions.ChangeSetNotFoundException:
            break  # an executed change set is removed with the stack's others
        if cs.get("ExecutionStatus") != "AVAILABLE":
            break
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"stack {stack} beginning change set {cs_name}: the run budget "
                               "ended first; not graded")
        assert time.time() < deadline, f"stack {stack} never began executing change set {cs_name}"
        time.sleep(0.5)


def _wait_terminal(ctx, cfn, stack: str, timeout: float = 600.0) -> str:
    deadline = time.time() + _budget_s(ctx, timeout)
    while True:
        try:
            s = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except Exception as exc:  # deleted stacks vanish from DescribeStacks by name
            if "does not exist" in str(exc):
                return "DELETE_COMPLETE"
            raise
        if s in _TERMINAL:
            return s
        if time.time() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"stack {stack} reaching a terminal status: the run budget ended "
                               "first; not graded")
        assert time.time() < deadline, f"stack {stack} still {s!r} at its wait deadline"
        time.sleep(1)


def _all_events(cfn, stack: str) -> list:
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        events.extend(page["StackEvents"])
    return events  # newest first


def _failure_events(cfn, stack: str) -> list:
    """Resource *_FAILED events of the most recent stack operation (newest first)."""
    out = []
    for e in _all_events(cfn, stack):
        if e["LogicalResourceId"] == stack and e["ResourceStatus"] in (
                "CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS") and e.get("ResourceStatusReason") == "User Initiated":
            break
        if e["LogicalResourceId"] != stack and e["ResourceStatus"].endswith("_FAILED"):
            out.append(e)
    return out


def _outputs(cfn, stack: str) -> dict:
    desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _physical_id(cfn, stack: str, logical: str) -> str:
    return cfn.describe_stack_resource(StackName=stack, LogicalResourceId=logical)[
        "StackResourceDetail"]["PhysicalResourceId"]


def _list_data_sources(appsync, api_id: str) -> list:
    out, token = [], None
    while True:
        r = appsync.list_data_sources(apiId=api_id, **({"nextToken": token} if token else {}))
        out.extend(r.get("dataSources", []))
        token = r.get("nextToken")
        if not token:
            return out


def _api_id_from_arn(arn: str) -> str:
    parts = arn.split(":", 5)
    assert len(parts) == 6 and parts[2] == "appsync", f"not an AppSync ARN: {arn!r}"
    kind, _, ident = parts[5].partition("/")
    assert kind == "apis" and ident and "/" not in ident, f"not a GraphQL API ARN: {arn!r}"
    return ident


def _direct_schema_creation(ctx, appsync, sdl: str) -> tuple:
    """(status, details) of GetSchemaCreationStatus once StartSchemaCreation of ``sdl`` on a scratch
    API leaves PROCESSING."""
    api_id = appsync.create_graphql_api(name=ctx.unique_name("sim2real-appsync2-sdl-"),
                                        authenticationType="API_KEY",
                                        tags={"sim2real": CHECK})["graphqlApi"]["apiId"]

    def _delete():
        code = _error_code(lambda: appsync.delete_graphql_api(apiId=api_id))
        if code not in ("<call succeeded>", "NotFoundException"):
            raise RuntimeError(f"appsync api {api_id} teardown failed: {code}")

    ctx.on_cleanup(_delete)
    appsync.start_schema_creation(apiId=api_id, definition=sdl.encode("utf-8"))
    deadline = time.time() + _budget_s(ctx, 120)
    while True:
        r = appsync.get_schema_creation_status(apiId=api_id)
        if r.get("status") == "PROCESSING" and time.time() > deadline and _budget_spent(ctx):
            raise TimeoutError("schema creation leaving PROCESSING: the run budget ended first; "
                               "not graded")
        if r.get("status") != "PROCESSING" or time.time() > deadline:
            return r.get("status"), r.get("details")
        time.sleep(1)


def _error_code(fn) -> str:
    try:
        fn()
    except Exception as exc:  # botocore ClientError carries .response
        resp = getattr(exc, "response", None)
        if resp is None:
            raise
        return resp.get("Error", {}).get("Code") or "<no error code>"
    return "<call succeeded>"


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _graphql(ctx, url: str, api_key: str, query: str, variables: dict | None = None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    routed_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(routed_url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "x-api-key": api_key,
                                          **route_headers})
    last = None
    deadline = time.time() + _budget_s(ctx, 30)
    while True:  # a freshly minted API key can take a few seconds to be honoured
        try:
            with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last = (exc.code, json.loads(exc.read().decode("utf-8") or "{}"))
            if exc.code != 401:
                return last
        if time.time() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("a fresh API key being honoured: the run budget ended first; "
                                   "not graded")
            return last
        time.sleep(1)


def _delete_stack(cfn, stack: str) -> None:
    try:
        cfn.delete_stack(StackName=stack)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except Exception as exc:
        raise RuntimeError(f"cloudformation stack {stack} teardown failed: {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
