"""deploy-entityresolution-namespace-workflow-policy-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-entityresolution-namespace-workflow-policy-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "entityresolution"]

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










@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Entity Resolution ID namespace, matching workflow and policy read back.

    Refs and GetAtt ARNs match independent listings, and deleting the stack removes them.
    """
    cfn = ctx.client("cloudformation")
    er = ctx.client("entityresolution")
    account = ctx.account
    stack_name = ctx.unique_name("sim2real-behav-cfn-ernwp-")
    bucket = ctx.unique_name("sim2real-behav-cfn-ernwp-").lower()[:63]
    db_name = ctx.unique_name("sim2real_behav_cfn_ernwp_").replace("-", "_")
    table_name = "records"
    role_name = ctx.unique_name("sim2real-behav-cfn-ernwp-")
    schema_name = ctx.unique_name("sim2real-behav-cfn-ernwp-")
    namespace_name = ctx.unique_name("sim2real-behav-cfn-ernwp-")
    workflow_name = ctx.unique_name("sim2real-behav-cfn-ernwp-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "entityresolution.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "glue:GetTable", "glue:GetDatabase", "glue:GetPartitions",
                "s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation",
            ],
            "Resource": [
                {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
                {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}/*"},
                {"Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog"},
                {"Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:"
                            "database/${GlueDatabase}"},
                {"Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:"
                            "table/${GlueDatabase}/*"},
            ],
        }],
    }

    template = json.dumps({
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {
                "BucketName": bucket,
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True, "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True, "RestrictPublicBuckets": True},
            }},
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {"CatalogId": account, "DatabaseInput": {"Name": db_name}},
            },
            "GlueTable": {
                "Type": "AWS::Glue::Table",
                "Properties": {
                    "CatalogId": account,
                    "DatabaseName": {"Ref": "GlueDatabase"},
                    "TableInput": {
                        "Name": table_name,
                        "TableType": "EXTERNAL_TABLE",
                        "StorageDescriptor": {
                            "Columns": [
                                {"Name": "recid", "Type": "string"},
                                {"Name": "email", "Type": "string"},
                            ],
                            "Location": {"Fn::Sub": f"s3://${{Bucket}}/{table_name}/"},
                            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                            "SerdeInfo": {
                                "SerializationLibrary": "org.apache.hadoop.hive.serde2.OpenCSVSerde"
                            },
                        },
                    },
                },
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": trust_policy,
                    "Policies": [{"PolicyName": "er-access", "PolicyDocument": access_policy}],
                },
            },
            "Mapping": {
                "Type": "AWS::EntityResolution::SchemaMapping",
                "Properties": {
                    "SchemaName": schema_name,
                    "MappedInputFields": [
                        {"FieldName": "recid", "Type": "UNIQUE_ID"},
                        {"FieldName": "email", "Type": "EMAIL_ADDRESS", "MatchKey": "email"},
                    ],
                },
            },
            "Namespace": {
                "Type": "AWS::EntityResolution::IdNamespace",
                "Properties": {
                    "IdNamespaceName": namespace_name,
                    "Type": "SOURCE",
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "InputSourceConfig": [{
                        "InputSourceARN": {
                            "Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:table/"
                                       "${GlueDatabase}/${GlueTable}"
                        },
                        "SchemaName": {"Ref": "Mapping"},
                    }],
                    "IdMappingWorkflowProperties": [{
                        "IdMappingType": "RULE_BASED",
                        "RuleBasedProperties": {
                            "AttributeMatchingModel": "ONE_TO_ONE",
                            "RecordMatchingModels": ["ONE_SOURCE_TO_ONE_TARGET"],
                            "RuleDefinitionTypes": ["SOURCE"],
                            "Rules": [{"RuleName": "emailRule", "MatchingKeys": ["email"]}],
                        },
                    }],
                },
            },
            "Workflow": {
                "Type": "AWS::EntityResolution::MatchingWorkflow",
                "Properties": {
                    "WorkflowName": workflow_name,
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "InputSourceConfig": [{
                        "InputSourceARN": {
                            "Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:table/"
                                       "${GlueDatabase}/${GlueTable}"
                        },
                        "SchemaArn": {"Fn::GetAtt": ["Mapping", "SchemaArn"]},
                    }],
                    "OutputSourceConfig": [{
                        "OutputS3Path": {"Fn::Sub": "s3://${Bucket}/output/"},
                        "Output": [{"Name": "recid"}, {"Name": "email"}],
                    }],
                    "ResolutionTechniques": {
                        "ResolutionType": "RULE_MATCHING",
                        "RuleBasedProperties": {
                            "AttributeMatchingModel": "ONE_TO_ONE",
                            "Rules": [{"RuleName": "emailRule", "MatchingKeys": ["email"]}],
                        },
                    },
                },
            },
            "Policy": {
                "Type": "AWS::EntityResolution::PolicyStatement",
                "Properties": {
                    "Arn": {"Fn::GetAtt": ["Workflow", "WorkflowArn"]},
                    "StatementId": "stmtA",
                    "Effect": "Allow",
                    "Action": ["entityresolution:GetMatchingWorkflow", "entityresolution:GetPolicy"],
                    "Principal": [account],
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "NamespaceRef": {"Value": {"Ref": "Namespace"}},
            "NamespaceArn": {"Value": {"Fn::GetAtt": ["Namespace", "IdNamespaceArn"]}},
            "WorkflowRef": {"Value": {"Ref": "Workflow"}},
            "WorkflowArn": {"Value": {"Fn::GetAtt": ["Workflow", "WorkflowArn"]}},
        },
    })

    stack_id = create_stack(ctx, cfn, stack_name, template, Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Refs and GetAtt ARNs against independent listings by the declared names.
    namespaces = [n["idNamespaceArn"] for n in paginate(
        er, "list_id_namespaces", "idNamespaceSummaries") if n["idNamespaceName"] == namespace_name]
    assert (outputs["NamespaceRef"], namespaces) == (namespace_name, [outputs["NamespaceArn"]]), (
        f"Ref {outputs['NamespaceRef']!r}, ListIdNamespaces {namespaces!r}"
    )
    workflows = [w["workflowArn"] for w in paginate(
        er, "list_matching_workflows", "workflowSummaries") if w["workflowName"] == workflow_name]
    assert (outputs["WorkflowRef"], workflows) == (workflow_name, [outputs["WorkflowArn"]]), (
        f"Ref {outputs['WorkflowRef']!r}, ListMatchingWorkflows {workflows!r}"
    )

    got_ns = er.get_id_namespace(idNamespaceName=namespace_name)
    ns_rules = got_ns["idMappingWorkflowProperties"][0]["ruleBasedProperties"]
    have_ns = (got_ns["type"], got_ns["roleArn"],
               [s["schemaName"] for s in got_ns["inputSourceConfig"]],
               got_ns["idMappingWorkflowProperties"][0]["idMappingType"],
               ns_rules["attributeMatchingModel"], ns_rules["recordMatchingModels"],
               ns_rules["ruleDefinitionTypes"],
               [(r["ruleName"], r["matchingKeys"]) for r in ns_rules["rules"]])
    want_ns = ("SOURCE", outputs["RoleArn"], [schema_name], "RULE_BASED", "ONE_TO_ONE",
               ["ONE_SOURCE_TO_ONE_TARGET"], ["SOURCE"], [("emailRule", ["email"])])
    assert have_ns == want_ns, f"GetIdNamespace {have_ns!r}, expected {want_ns!r}"

    got_wf = er.get_matching_workflow(workflowName=workflow_name)
    wf_rules = got_wf["resolutionTechniques"]["ruleBasedProperties"]
    have_wf = (got_wf["roleArn"], got_wf["resolutionTechniques"]["resolutionType"],
               wf_rules["attributeMatchingModel"],
               [(r["ruleName"], r["matchingKeys"]) for r in wf_rules["rules"]],
               [o["outputS3Path"] for o in got_wf["outputSourceConfig"]])
    want_wf = (outputs["RoleArn"], "RULE_MATCHING", "ONE_TO_ONE", [("emailRule", ["email"])],
               [f"s3://{bucket}/output/"])
    assert have_wf == want_wf, f"GetMatchingWorkflow {have_wf!r}, expected {want_wf!r}"

    policy_doc = json.loads(er.get_policy(arn=outputs["WorkflowArn"])["policy"])
    stmt = [(s.get("Effect"), sorted(s["Action"] if isinstance(s["Action"], list) else [s["Action"]]))
            for s in policy_doc["Statement"] if s.get("Sid") == "stmtA"]
    want_stmt = [("Allow", ["entityresolution:GetMatchingWorkflow", "entityresolution:GetPolicy"])]
    assert stmt == want_stmt, f"policy statement stmtA {stmt!r}, expected {want_stmt!r}"

    delete_stack(cfn, stack_id)
    not_found = ("ResourceNotFoundException", "IdNamespace Not Found")
    expect_error(lambda: er.get_id_namespace(idNamespaceName=namespace_name), *not_found)
    not_found_2 = ("ResourceNotFoundException", "MatchingWorkflow Not Found")
    expect_error(lambda: er.get_matching_workflow(workflowName=workflow_name), *not_found_2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
