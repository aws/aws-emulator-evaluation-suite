"""deploy-connect-instance-and-core-resource-types-round-trip-and-delete."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-connect-instance-and-core-resource-types-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "connect"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_FLOW_CONTENT = json.dumps({
    "Version": "2019-10-30",
    "StartAction": "11111111-1111-1111-1111-111111111111",
    "Actions": [
        {
            "Identifier": "11111111-1111-1111-1111-111111111111",
            "Type": "DisconnectParticipant",
            "Parameters": {},
            "Transitions": {},
        }
    ],
})
_MODULE_CONTENT = json.dumps({
    "Version": "2019-10-30",
    "StartAction": "22222222-2222-2222-2222-222222222222",
    "Actions": [
        {
            "Identifier": "22222222-2222-2222-2222-222222222222",
            "Type": "DisconnectParticipant",
            "Parameters": {},
            "Transitions": {},
        }
    ],
    "Settings": {},
})


_CHILDREN = ("HoursOfOperation", "Queue", "RoutingProfile", "SecurityProfile",
             "UserHierarchyStructure", "UserHierarchyGroup", "ApprovedOrigin", "ContactFlow",
             "ContactFlowModule", "User")
_ORIGIN = "https://example.com"


def _template(n, children=True):
    """Every name in ``n``; the user's password is a NoEcho parameter, never a template literal.

    Without ``children`` only the instance and its agent status remain: Connect has no delete
    for an agent status, so the instance's own delete is what removes it.
    """
    alias, hop_name, queue_name, rp_name, rp_description = (
        n["alias"], n["hop"], n["queue"], n["rp"], n["rp_description"])
    sp_name, hierarchy_level_name, uhg_name, origin = n["sp"], n["level"], n["uhg"], _ORIGIN
    flow_name, module_name, status_name, username = n["flow"], n["module"], n["status"], n["user"]
    resources = {
            "Instance": {
                "Type": "AWS::Connect::Instance",
                "Properties": {
                    "IdentityManagementType": "CONNECT_MANAGED",
                    "InstanceAlias": alias,
                    "Attributes": {"InboundCalls": False, "OutboundCalls": False},
                },
            },
            "HoursOfOperation": {
                "Type": "AWS::Connect::HoursOfOperation",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "Name": hop_name,
                    "TimeZone": "UTC",
                    "Config": [{
                        "Day": "MONDAY",
                        "StartTime": {"Hours": 0, "Minutes": 0},
                        "EndTime": {"Hours": 23, "Minutes": 59},
                    }],
                },
            },
            "Queue": {
                "Type": "AWS::Connect::Queue",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "HoursOfOperationArn": {"Ref": "HoursOfOperation"},
                    "Name": queue_name,
                },
            },
            "RoutingProfile": {
                "Type": "AWS::Connect::RoutingProfile",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "Name": rp_name,
                    "Description": rp_description,
                    "MediaConcurrencies": [{"Channel": "VOICE", "Concurrency": 1}],
                    "DefaultOutboundQueueArn": {"Ref": "Queue"},
                    "QueueConfigs": [{
                        "QueueReference": {"QueueArn": {"Ref": "Queue"}, "Channel": "VOICE"},
                        "Priority": 1,
                        "Delay": 0,
                    }],
                },
            },
            "SecurityProfile": {
                "Type": "AWS::Connect::SecurityProfile",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "SecurityProfileName": sp_name,
                },
            },
            "UserHierarchyStructure": {
                "Type": "AWS::Connect::UserHierarchyStructure",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "UserHierarchyStructure": {"LevelOne": {"Name": hierarchy_level_name}},
                },
            },
            "UserHierarchyGroup": {
                "Type": "AWS::Connect::UserHierarchyGroup",
                "DependsOn": "UserHierarchyStructure",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "Name": uhg_name,
                },
            },
            "ApprovedOrigin": {
                "Type": "AWS::Connect::ApprovedOrigin",
                "Properties": {
                    "InstanceId": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "Origin": origin,
                },
            },
            "ContactFlow": {
                "Type": "AWS::Connect::ContactFlow",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "Name": flow_name,
                    "Type": "CONTACT_FLOW",
                    "Content": _FLOW_CONTENT,
                },
            },
            "ContactFlowModule": {
                "Type": "AWS::Connect::ContactFlowModule",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "Name": module_name,
                    "Content": _MODULE_CONTENT,
                },
            },
            "AgentStatus": {
                "Type": "AWS::Connect::AgentStatus",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "Name": status_name,
                    "State": "ENABLED",
                },
            },
            "User": {
                "Type": "AWS::Connect::User",
                "Properties": {
                    "InstanceArn": {"Fn::GetAtt": ["Instance", "Arn"]},
                    "Username": username,
                    "Password": {"Ref": "UserPassword"},
                    "RoutingProfileArn": {"Ref": "RoutingProfile"},
                    "SecurityProfileArns": [{"Ref": "SecurityProfile"}],
                    "HierarchyGroupArn": {"Ref": "UserHierarchyGroup"},
                    "PhoneConfig": {"PhoneType": "SOFT_PHONE", "AutoAccept": False},
                    "IdentityInfo": {"FirstName": "Sim", "LastName": "Real"},
                },
            },
    }
    outputs = {
        "InstanceRef": {"Value": {"Ref": "Instance"}},
        "InstanceArn": {"Value": {"Fn::GetAtt": ["Instance", "Arn"]}},
        "InstanceServiceRole": {"Value": {"Fn::GetAtt": ["Instance", "ServiceRole"]}},
        "InstanceStatusOut": {"Value": {"Fn::GetAtt": ["Instance", "InstanceStatus"]}},
        "AgentStatusArn": {"Value": {"Ref": "AgentStatus"}},
        "AgentStatusArnAtt": {"Value": {"Fn::GetAtt": ["AgentStatus", "AgentStatusArn"]}},
    }
    if children:
        outputs.update({
            "HoursOfOperationArn": {"Value": {"Ref": "HoursOfOperation"}},
            "QueueArn": {"Value": {"Ref": "Queue"}},
            "QueueType": {"Value": {"Fn::GetAtt": ["Queue", "Type"]}},
            "RoutingProfileArn": {"Value": {"Ref": "RoutingProfile"}},
            "SecurityProfileArn": {"Value": {"Ref": "SecurityProfile"}},
            "SecurityProfileArnAtt": {"Value": {"Fn::GetAtt": ["SecurityProfile",
                                                               "SecurityProfileArn"]}},
            "StructureRef": {"Value": {"Ref": "UserHierarchyStructure"}},
            "UserHierarchyGroupArn": {"Value": {"Ref": "UserHierarchyGroup"}},
            "ApprovedOriginRef": {"Value": {"Ref": "ApprovedOrigin"}},
            "ContactFlowArn": {"Value": {"Ref": "ContactFlow"}},
            "ContactFlowModuleArn": {"Value": {"Ref": "ContactFlowModule"}},
            "ContactFlowModuleStatus": {"Value": {"Fn::GetAtt": ["ContactFlowModule", "Status"]}},
            "UserArn": {"Value": {"Ref": "User"}},
            "UserArnAtt": {"Value": {"Fn::GetAtt": ["User", "UserArn"]}},
        })
    else:
        resources = {k: v for k, v in resources.items() if k not in _CHILDREN}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"UserPassword": {"Type": "String", "NoEcho": True}},
        "Resources": resources,
        "Outputs": outputs,
    })


def _named(connect, op, key, instance_id, name, name_key="Name", **kw):
    """The ARNs of ``op``'s entries named ``name`` on the instance, across every page."""
    return [e["Arn"] for e in paginate(connect, op, key, InstanceId=instance_id, **kw)
            if e[name_key] == name]


def _resource_id(arn):
    """The trailing path segment of a Connect resource ARN."""
    return arn.rsplit("/", 1)[-1]


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Eleven CloudFormation Connect resource types read back through Connect, then delete child-first.

    Each Ref matches a Connect list entry and properties read back; an update drops ten children
    (the hierarchy structure keeps its level) and the stack delete removes the instance.
    """
    cfn = ctx.client("cloudformation")
    connect = ctx.client("connect")
    n = {k: ctx.unique_name(f"sim2real-behav-{k}-") for k in (
        "hop", "queue", "rp", "sp", "uhg", "level", "flow", "module", "status", "user")}
    n["alias"] = ctx.unique_name("sim2real-cxn-")
    n["rp_description"] = ctx.unique_name("sim2real-desc-")
    params = [{"ParameterKey": "UserPassword",
               "ParameterValue": f"Sim2Real-{secrets.token_urlsafe(18)}-1a!"}]

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cxnstk-"), _template(n),
                            Parameters=params)
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    # Instance: Ref and the Arn GetAtt against the ListInstances entry by alias.
    instances = [i for i in paginate(connect, "list_instances", "InstanceSummaryList")
                 if i.get("InstanceAlias") == n["alias"]]
    assert [i["Arn"] for i in instances] == [out["InstanceRef"]] == [out["InstanceArn"]], (
        f"ListInstances with alias {n['alias']!r}: {instances!r}; outputs {out!r}"
    )
    instance_id = instances[0]["Id"]
    instance = connect.describe_instance(InstanceId=instance_id)["Instance"]
    got = (instance["ServiceRole"], instance["InstanceStatus"], instance["IdentityManagementType"],
           instance["InstanceAlias"], instance["InboundCallsEnabled"], instance["OutboundCallsEnabled"])
    want = (out["InstanceServiceRole"], out["InstanceStatusOut"], "CONNECT_MANAGED", n["alias"],
            False, False)
    assert got == want and out["InstanceStatusOut"] == "ACTIVE", f"DescribeInstance {got!r}"
    instance_arn = instance["Arn"]

    # HoursOfOperation.
    hop_arn = out["HoursOfOperationArn"]
    listed = _named(connect, "list_hours_of_operations", "HoursOfOperationSummaryList", instance_id,
                    n["hop"])
    assert listed == [hop_arn], (
        f"HoursOfOperation entries listed {listed!r}, Ref {hop_arn!r}"
    )
    hop_id = _resource_id(hop_arn)
    hop = connect.describe_hours_of_operation(InstanceId=instance_id,
                                              HoursOfOperationId=hop_id)["HoursOfOperation"]
    got = (hop["Name"], hop["TimeZone"], hop["Config"])
    want = (n["hop"], "UTC", [{"Day": "MONDAY", "StartTime": {"Hours": 0, "Minutes": 0},
                               "EndTime": {"Hours": 23, "Minutes": 59}}])
    assert got == want, f"DescribeHoursOfOperation {got!r}"

    # Queue: the Type GetAtt against the ListQueues QueueType.
    queue_arn = out["QueueArn"]
    queues = [q for q in paginate(connect, "list_queues", "QueueSummaryList", InstanceId=instance_id,
                                  QueueTypes=["STANDARD"]) if q.get("Name") == n["queue"]]
    assert [(q["Arn"], q["QueueType"]) for q in queues] == [(queue_arn, out["QueueType"])], (
        f"ListQueues named {n['queue']!r}: {queues!r}; GetAtt Type {out['QueueType']!r}"
    )
    assert out["QueueType"] == "STANDARD", f"GetAtt Queue.Type {out['QueueType']!r}"
    queue_id = _resource_id(queue_arn)
    queue = connect.describe_queue(InstanceId=instance_id, QueueId=queue_id)["Queue"]
    got = (queue["Name"], queue["HoursOfOperationId"], queue["Status"])
    assert got == (n["queue"], hop_id, "ENABLED"), f"DescribeQueue {got!r}"

    # RoutingProfile and its queue association.
    rp_arn = out["RoutingProfileArn"]
    listed = _named(connect, "list_routing_profiles", "RoutingProfileSummaryList", instance_id,
                    n["rp"])
    assert listed == [rp_arn], (
        f"RoutingProfile entries listed {listed!r}, Ref {rp_arn!r}"
    )
    rp_id = _resource_id(rp_arn)
    rp = connect.describe_routing_profile(InstanceId=instance_id,
                                          RoutingProfileId=rp_id)["RoutingProfile"]
    got = (rp["Name"], rp["Description"], rp["DefaultOutboundQueueId"],
           [(m["Channel"], m["Concurrency"]) for m in rp["MediaConcurrencies"]])
    assert got == (n["rp"], n["rp_description"], queue_id, [("VOICE", 1)]), (
        f"DescribeRoutingProfile {got!r}"
    )
    rp_queues = paginate(connect, "list_routing_profile_queues", "RoutingProfileQueueConfigSummaryList",
                         InstanceId=instance_id, RoutingProfileId=rp_id)
    got = [(q["QueueId"], q["Channel"], q["Priority"], q["Delay"]) for q in rp_queues]
    assert got == [(queue_id, "VOICE", 1, 0)], f"ListRoutingProfileQueues {got!r}"

    # SecurityProfile: the SecurityProfileArn GetAtt too.
    sp_arn = out["SecurityProfileArn"]
    listed = _named(connect, "list_security_profiles", "SecurityProfileSummaryList", instance_id,
                    n["sp"])
    assert listed == [sp_arn] == [out["SecurityProfileArnAtt"]], (
        f"SecurityProfile entries listed {listed!r}, Ref {sp_arn!r}, "
        f"GetAtt {out['SecurityProfileArnAtt']!r}"
    )
    sp_id = _resource_id(sp_arn)

    # UserHierarchyStructure: Ref is the structure's ARN under the instance.
    assert out["StructureRef"] == f"{instance_arn}/user-hierarchy-structure", (
        f"UserHierarchyStructure Ref {out['StructureRef']!r}"
    )
    structure = connect.describe_user_hierarchy_structure(InstanceId=instance_id)["HierarchyStructure"]
    assert structure["LevelOne"]["Name"] == n["level"], f"hierarchy structure {structure!r}"

    # UserHierarchyGroup.
    uhg_arn = out["UserHierarchyGroupArn"]
    listed = _named(connect, "list_user_hierarchy_groups", "UserHierarchyGroupSummaryList",
                    instance_id, n["uhg"])
    assert listed == [uhg_arn], (
        f"UserHierarchyGroup entries listed {listed!r}, Ref {uhg_arn!r}"
    )
    uhg_id = _resource_id(uhg_arn)

    # ApprovedOrigin: Ref is InstanceId|Origin, and the instance lists exactly that origin.
    assert out["ApprovedOriginRef"] == f"{instance_arn}|{_ORIGIN}", (
        f"ApprovedOrigin Ref {out['ApprovedOriginRef']!r}"
    )
    origins = paginate(connect, "list_approved_origins", "Origins", InstanceId=instance_id)
    assert origins == [_ORIGIN], f"ListApprovedOrigins {origins!r}"

    # ContactFlow and ContactFlowModule.
    flow_arn = out["ContactFlowArn"]
    listed = _named(connect, "list_contact_flows", "ContactFlowSummaryList", instance_id,
                    n["flow"])
    assert listed == [flow_arn], (
        f"ContactFlow entries listed {listed!r}, Ref {flow_arn!r}"
    )
    flow = connect.describe_contact_flow(InstanceId=instance_id,
                                         ContactFlowId=_resource_id(flow_arn))["ContactFlow"]
    got = (flow["Name"], flow["Type"], json.loads(flow["Content"]))
    assert got == (n["flow"], "CONTACT_FLOW", json.loads(_FLOW_CONTENT)), f"DescribeContactFlow {got!r}"
    module_arn = out["ContactFlowModuleArn"]
    listed = _named(connect, "list_contact_flow_modules", "ContactFlowModulesSummaryList",
                    instance_id, n["module"])
    assert listed == [module_arn], (
        f"ContactFlowModule entries listed {listed!r}, Ref {module_arn!r}"
    )
    module = connect.describe_contact_flow_module(
        InstanceId=instance_id, ContactFlowModuleId=_resource_id(module_arn))["ContactFlowModule"]
    got = (module["Name"], json.loads(module["Content"]), module["Status"],
           out["ContactFlowModuleStatus"])
    assert got == (n["module"], json.loads(_MODULE_CONTENT), "published", "PUBLISHED"), (
        f"DescribeContactFlowModule {got!r}"
    )

    # AgentStatus: Ref and the AgentStatusArn GetAtt.
    status_arn = out["AgentStatusArn"]
    listed = _named(connect, "list_agent_statuses", "AgentStatusSummaryList", instance_id,
                    n["status"])
    assert listed == [status_arn] == [out["AgentStatusArnAtt"]], (
        f"AgentStatus entries listed {listed!r}, Ref {status_arn!r}, "
        f"GetAtt {out['AgentStatusArnAtt']!r}"
    )
    agent_status = connect.describe_agent_status(
        InstanceId=instance_id, AgentStatusId=_resource_id(status_arn))["AgentStatus"]
    got = (agent_status["Name"], agent_status["State"])
    assert got == (n["status"], "ENABLED"), f"DescribeAgentStatus {got!r}"

    # User: Ref and the UserArn GetAtt; every templated association and setting.
    user_arn = out["UserArn"]
    listed = _named(connect, "list_users", "UserSummaryList", instance_id, n["user"],
                    name_key="Username")
    assert listed == [user_arn] == [out["UserArnAtt"]], (
        f"User entries listed {listed!r}, Ref {user_arn!r}, GetAtt {out['UserArnAtt']!r}"
    )
    user = connect.describe_user(UserId=_resource_id(user_arn), InstanceId=instance_id)["User"]
    got = (user["Username"], user["RoutingProfileId"], user["SecurityProfileIds"],
           user["HierarchyGroupId"], user["PhoneConfig"]["PhoneType"],
           user["PhoneConfig"]["AutoAccept"], user["IdentityInfo"].get("FirstName"),
           user["IdentityInfo"].get("LastName"))
    want = (n["user"], rp_id, [sp_id], uhg_id, "SOFT_PHONE", False, "Sim", "Real")
    assert got == want, f"DescribeUser {got!r}, expected {want!r}"

    # Children first: the update drops the ten children; nine are gone from their instance lists
    # (the origins read empty) while the same instance still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(n, children=False),
                     Parameters=params)
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"child-dropping update ended {status!r}"
    after = connect.describe_instance(InstanceId=instance_id)["Instance"]
    assert after["CreatedTime"] == instance["CreatedTime"], f"the instance after the update {after!r}"
    left = {
        "hours": _named(connect, "list_hours_of_operations", "HoursOfOperationSummaryList",
                        instance_id, n["hop"]),
        "queue": _named(connect, "list_queues", "QueueSummaryList", instance_id, n["queue"]),
        "routing": _named(connect, "list_routing_profiles", "RoutingProfileSummaryList",
                          instance_id, n["rp"]),
        "security": _named(connect, "list_security_profiles", "SecurityProfileSummaryList",
                           instance_id, n["sp"]),
        "group": _named(connect, "list_user_hierarchy_groups", "UserHierarchyGroupSummaryList",
                        instance_id, n["uhg"]),
        "flow": _named(connect, "list_contact_flows", "ContactFlowSummaryList", instance_id,
                       n["flow"]),
        "module": _named(connect, "list_contact_flow_modules", "ContactFlowModulesSummaryList",
                         instance_id, n["module"]),
        "user": _named(connect, "list_users", "UserSummaryList", instance_id, n["user"],
                       name_key="Username"),
        "origins": paginate(connect, "list_approved_origins", "Origins", InstanceId=instance_id),
    }
    assert all(v == [] for v in left.values()), f"children left after the update: {left!r}"
    # Dropping AWS::Connect::UserHierarchyStructure leaves the instance's structure as it was:
    # AWS still describes the same LevelOne (Id, Arn, Name) after the update.
    kept_structure = connect.describe_user_hierarchy_structure(
        InstanceId=instance_id)["HierarchyStructure"]
    got = {k: {f: v.get(f) for f in ("Id", "Arn", "Name")} for k, v in kept_structure.items()}
    want = {"LevelOne": {f: structure["LevelOne"].get(f) for f in ("Id", "Arn", "Name")}}
    assert got == want, f"hierarchy structure after the update {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: connect.describe_instance(InstanceId=instance_id))
    instance_gone = ("ResourceNotFoundException", f"Instance {instance_id} not found")
    expect_error(lambda: connect.describe_instance(InstanceId=instance_id), *instance_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
