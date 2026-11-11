"""deploy-appsync-source-api-association-invalid-merge-type-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-appsync-source-api-association-invalid-merge-type-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """A SourceApiAssociation MergeType outside AUTO_MERGE/MANUAL_MERGE fails property validation.

    The stack deployed with MANUAL_MERGE merges; an update changing only MergeType is refused by
    early validation and leaves the same association merged, unchanged.
    """
    cfn = ctx.client("cloudformation")
    svc = ctx.client("appsync")
    stack = ctx.unique_name("sim2real-appsync-assoc-bad-")
    description = ctx.unique_name("sim2real-association-")

    # Positive control: the same template with a valid MergeType.
    stack_id = create_stack(ctx, cfn, stack, _template(stack, description),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    merged_id = out["MergedApiId"]
    before = _settled_association(svc, merged_id, out["AssociationId"])
    got = (before["sourceApiAssociationStatus"], before["sourceApiAssociationConfig"])
    assert got == ("MERGE_SUCCESS", {"mergeType": "MANUAL_MERGE"}), f"control reads {got!r}"

    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(stack, description, "NOT_A_REAL_MERGE_TYPE"),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"rejected update ended {status!r}"
    rows = validation_rows(cfn, stack_id)
    want = [("Association", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             "NOT_A_REAL_MERGE_TYPE is not a valid enum value. "
             "Supported values: [AUTO_MERGE, MANUAL_MERGE]",
             "/Resources/Association/Properties/SourceApiAssociationConfig/MergeType")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # The same association, still merged with MANUAL_MERGE and not re-merged.
    listed = _associations(svc, merged_id)
    assert [s["associationId"] for s in listed] == [out["AssociationId"]], f"listed {listed!r}"
    after = svc.get_source_api_association(
        mergedApiIdentifier=merged_id, associationId=out["AssociationId"])["sourceApiAssociation"]
    keys = ("sourceApiAssociationStatus", "sourceApiAssociationConfig", "lastSuccessfulMergeDate")
    assert [after[k] for k in keys] == [before[k] for k in keys], (
        f"association after the refused update {[after[k] for k in keys]!r}, "
        f"before {[before[k] for k in keys]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
