"""deploy-appsync-source-api-association-cfn-ref-and-attributes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appsync-source-api-association-cfn-ref-and-attributes"
GROUP = "deploy"
SERVICES = ["appsync", "cloudformation"]

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


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_TERMINAL_MERGE = ("MERGE_SUCCESS", "MERGE_FAILED", "AUTO_MERGE_SCHEDULE_FAILED")
_TAG_KEY = "sim2real-appsync"


def _js_literal(value):
    return (
        "export function request(ctx) {\n"
        f"  return {{ payload: '{value}' }};\n"
        "}\n"
        "export function response(ctx) {\n"
        "  return ctx.result;\n"
        "}\n"
    )


def _template(prefix, description, merge_type="MANUAL_MERGE", with_association=True) -> str:
    """One source GraphQLApi, one MERGED GraphQLApi and the SourceApiAssociation linking them."""
    api = {"Fn::GetAtt": ["SourceApi", "ApiId"]}
    merged_api = {"Fn::GetAtt": ["MergedApi", "ApiId"]}
    t = [{"Key": _TAG_KEY, "Value": prefix}]
    resources = {
        "SourceApi": {
            "Type": "AWS::AppSync::GraphQLApi",
            "Properties": {"Name": f"{prefix}-src", "AuthenticationType": "API_KEY", "Tags": t},
        },
        "SourceSchema": {
            "Type": "AWS::AppSync::GraphQLSchema",
            "Properties": {"ApiId": api, "Definition": "type Query {\n  greeting: String\n}\n"},
        },
        "NoneSource": {
            "Type": "AWS::AppSync::DataSource",
            "Properties": {"ApiId": api, "Name": "NoneSource", "Type": "NONE"},
        },
        "Resolver": {
            "Type": "AWS::AppSync::Resolver",
            "DependsOn": ["SourceSchema"],
            "Properties": {
                "ApiId": api, "TypeName": "Query", "FieldName": "greeting", "Kind": "UNIT",
                "DataSourceName": {"Fn::GetAtt": ["NoneSource", "Name"]},
                "Runtime": {"Name": "APPSYNC_JS", "RuntimeVersion": "1.0.0"},
                "Code": _js_literal(prefix),
            },
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
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": [
                        {"Effect": "Allow", "Action": "appsync:SourceGraphQL",
                         "Resource": [{"Fn::GetAtt": ["SourceApi", "Arn"]},
                                      {"Fn::Sub": "${SourceApi.Arn}/*"}]},
                        {"Effect": "Allow", "Action": "appsync:StartSchemaMerge",
                         "Resource": {"Fn::Sub": "arn:${AWS::Partition}:appsync:${AWS::Region}:"
                                      "${AWS::AccountId}:apis/*/sourceApiAssociations/*"}},
                    ]},
                }],
                "Tags": t,
            },
        },
        "MergedApi": {
            "Type": "AWS::AppSync::GraphQLApi",
            "Properties": {
                "Name": f"{prefix}-merged", "AuthenticationType": "API_KEY",
                "ApiType": "MERGED",
                "MergedApiExecutionRoleArn": {"Fn::GetAtt": ["MergedRole", "Arn"]},
                "Tags": t,
            },
        },
    }
    outputs = {
        "SourceApiId": {"Value": api},
        "SourceApiArn": {"Value": {"Fn::GetAtt": ["SourceApi", "Arn"]}},
        "MergedApiId": {"Value": merged_api},
        "MergedApiArn": {"Value": {"Fn::GetAtt": ["MergedApi", "Arn"]}},
    }
    if with_association:
        resources["Association"] = {
            "Type": "AWS::AppSync::SourceApiAssociation",
            "DependsOn": ["SourceSchema", "Resolver"],
            "Properties": {
                "SourceApiIdentifier": api,
                "MergedApiIdentifier": merged_api,
                "Description": description,
                "SourceApiAssociationConfig": {"MergeType": merge_type},
            },
        }
        outputs.update({
            "AssociationRef": {"Value": {"Ref": "Association"}},
            "AssociationArn": {"Value": {"Fn::GetAtt": ["Association", "AssociationArn"]}},
            "AssociationId": {"Value": {"Fn::GetAtt": ["Association", "AssociationId"]}},
            "AssociationMergedApiId": {"Value": {"Fn::GetAtt": ["Association", "MergedApiId"]}},
            "AssociationMergedApiArn": {"Value": {"Fn::GetAtt": ["Association", "MergedApiArn"]}},
            "AssociationSourceApiId": {"Value": {"Fn::GetAtt": ["Association", "SourceApiId"]}},
            "AssociationSourceApiArn": {"Value": {"Fn::GetAtt": ["Association", "SourceApiArn"]}},
        })
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _settled_association(svc, merged_id, association_id, timeout_s=300.0):
    """GetSourceApiAssociation polled to a terminal merge status."""
    deadline = time.monotonic() + timeout_s
    while True:
        assoc = svc.get_source_api_association(
            mergedApiIdentifier=merged_id, associationId=association_id)["sourceApiAssociation"]
        if assoc["sourceApiAssociationStatus"] in _TERMINAL_MERGE:
            return assoc
        if time.monotonic() > deadline:
            raise AssertionError(f"association still {assoc['sourceApiAssociationStatus']!r}")
        time.sleep(5)


def _associations(svc, merged_id):
    return paginate(svc, "list_source_api_associations", "sourceApiAssociationSummaries",
                    apiId=merged_id)


@tags("axis:happy-path", "concern:deploy", "concern:representation", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AppSync SourceApiAssociation reads back through AppSync, then deletes.

    Its Ref, GetAtts and templated properties match the listed, merged association; an update
    dropping it removes it from the live merged API, and the stack delete removes both APIs.
    """
    cfn = ctx.client("cloudformation")
    svc = ctx.client("appsync")
    stack = ctx.unique_name("sim2real-appsync-assoc-")
    description = ctx.unique_name("sim2real-association-")

    stack_id = create_stack(ctx, cfn, stack, _template(stack, description),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    merged_id, source_id = out["MergedApiId"], out["SourceApiId"]

    # Ref against the merged API's own listing; GetAtts against GetSourceApiAssociation.
    listed = _associations(svc, merged_id)
    got = [(s["associationArn"], s["description"]) for s in listed]
    assert got == [(out["AssociationRef"], description)], f"associations listed {got!r}"
    assert out["AssociationRef"] == out["AssociationArn"], (
        f"Ref {out['AssociationRef']!r} != GetAtt AssociationArn {out['AssociationArn']!r}"
    )
    assoc = _settled_association(svc, merged_id, listed[0]["associationId"])
    got = (assoc["associationArn"], assoc["associationId"], assoc["mergedApiArn"],
           assoc["sourceApiArn"], assoc["mergedApiId"], assoc["sourceApiId"],
           assoc["description"], assoc["sourceApiAssociationConfig"],
           assoc["sourceApiAssociationStatus"])
    want = (out["AssociationRef"], out["AssociationId"], out["AssociationMergedApiArn"],
            out["AssociationSourceApiArn"], out["AssociationMergedApiId"],
            out["AssociationSourceApiId"], description, {"mergeType": "MANUAL_MERGE"},
            "MERGE_SUCCESS")
    assert got == want, f"association reads {got!r}, expected {want!r}"
    apis = (out["MergedApiArn"], out["SourceApiArn"], merged_id, source_id)
    assert apis == (assoc["mergedApiArn"], assoc["sourceApiArn"], assoc["mergedApiId"],
                    assoc["sourceApiId"]), f"API GetAtts {apis!r} differ from the association"

    # Child before parent: the update drops only the association; the live merged API lists none.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, description,
                                                                with_association=False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"association-removing update ended {status!r}"
    live_id = svc.get_graphql_api(apiId=merged_id)["graphqlApi"]["apiId"]
    assert live_id == merged_id, f"merged API id after the update {live_id!r} != {merged_id!r}"
    left = _associations(svc, merged_id)
    assert left == [], f"associations of the live merged API after the update: {left!r}"

    delete_stack(cfn, stack_id)
    for api_id in (merged_id, source_id):
        refused = ("NotFoundException", "API not found.")
        expect_error(lambda: svc.get_graphql_api(apiId=api_id), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
