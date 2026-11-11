"""deploy-groundstation-dataflowendpointgroup-and-missionprofile-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-groundstation-dataflowendpointgroup-and-missionprofile-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "groundstation"]

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

_VPC_CIDR = "10.96.0.0/16"
_SUBNET_CIDR = "10.96.1.0/24"
_ADDRESS = "10.96.1.5"
_PORT = 55888
_PRE_PASS_S = 150
_POST_PASS_S = 130
_MIN_CONTACT_S = 30
_CENTER_FREQUENCY_MHZ = 7800.0
_BANDWIDTH_MHZ = 1.0


def _template(names, with_profile=True):
    endpoint_name, tracking_name, antenna_name, dfe_name, mp_name, role_name = names
    t = [{"Key": "sim2real-gs", "Value": mp_name}]
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "Subnet": {"Type": "AWS::EC2::Subnet",
                  "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR}},
        "Sg": {"Type": "AWS::EC2::SecurityGroup",
              "Properties": {"VpcId": {"Ref": "Vpc"},
                              "GroupDescription": "sim2real groundstation dataflow sg"}},
        "Role": {"Type": "AWS::IAM::Role", "Properties": {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "groundstation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }]},
            "Policies": [{"PolicyName": "sim2real-groundstation-eni-policy",
                          "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                              "Effect": "Allow",
                              "Action": [
                                  "ec2:CreateNetworkInterface",
                                  "ec2:DeleteNetworkInterface",
                                  "ec2:CreateNetworkInterfacePermission",
                                  "ec2:DeleteNetworkInterfacePermission",
                                  "ec2:DescribeSubnets",
                                  "ec2:DescribeVpcs",
                                  "ec2:DescribeSecurityGroups",
                                  "ec2:DescribeNetworkInterfaces",
                              ],
                              "Resource": "*",
                          }]}}],
        }},
        "TrackingCfg": {"Type": "AWS::GroundStation::Config", "Properties": {
            "Name": tracking_name,
            "ConfigData": {"TrackingConfig": {"Autotrack": "PREFERRED"}},
        }},
        "AntennaCfg": {"Type": "AWS::GroundStation::Config", "Properties": {
            "Name": antenna_name,
            "ConfigData": {"AntennaDownlinkConfig": {"SpectrumConfig": {
                "CenterFrequency": {"Value": _CENTER_FREQUENCY_MHZ, "Units": "MHz"},
                "Bandwidth": {"Value": _BANDWIDTH_MHZ, "Units": "MHz"},
                "Polarization": "NONE",
            }}},
        }},
        "DfeCfg": {"Type": "AWS::GroundStation::Config", "Properties": {
            "Name": dfe_name,
            "ConfigData": {"DataflowEndpointConfig": {"DataflowEndpointName": endpoint_name}},
        }},
        "Group": {"Type": "AWS::GroundStation::DataflowEndpointGroup", "Properties": {
            "ContactPrePassDurationSeconds": _PRE_PASS_S,
            "ContactPostPassDurationSeconds": _POST_PASS_S,
            "EndpointDetails": [{
                "Endpoint": {"Name": endpoint_name,
                            "Address": {"Name": _ADDRESS, "Port": _PORT}, "Mtu": 1500},
                "SecurityDetails": {"SubnetIds": [{"Ref": "Subnet"}],
                                    "SecurityGroupIds": [{"Ref": "Sg"}],
                                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]}},
            }],
            "Tags": t,
        }},
    }
    outputs = {
        "GroupRef": {"Value": {"Ref": "Group"}},
        "GroupArn": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
        "GroupId": {"Value": {"Fn::GetAtt": ["Group", "Id"]}},
        "TrackingArn": {"Value": {"Ref": "TrackingCfg"}},
        "AntennaArn": {"Value": {"Ref": "AntennaCfg"}},
        "DfeArn": {"Value": {"Ref": "DfeCfg"}},
        "SubnetId": {"Value": {"Ref": "Subnet"}},
        "SgId": {"Value": {"Ref": "Sg"}},
    }
    if with_profile:
        resources["MissionProfile"] = {
            "Type": "AWS::GroundStation::MissionProfile", "Properties": {
                "Name": mp_name,
                "MinimumViableContactDurationSeconds": _MIN_CONTACT_S,
                "TrackingConfigArn": {"Ref": "TrackingCfg"},
                "DataflowEdges": [{"Source": {"Ref": "AntennaCfg"},
                                   "Destination": {"Ref": "DfeCfg"}}],
                "Tags": t,
            },
        }
        outputs.update({
            "MpRef": {"Value": {"Ref": "MissionProfile"}},
            "MpArn": {"Value": {"Fn::GetAtt": ["MissionProfile", "Arn"]}},
            "MpId": {"Value": {"Fn::GetAtt": ["MissionProfile", "Id"]}},
            "MpRegion": {"Value": {"Fn::GetAtt": ["MissionProfile", "Region"]}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DataflowEndpointGroup and MissionProfile read back through GroundStation.

    Refs match independent list entries; endpoint, security details, Configs, edges and tags read
    back; an update dropping the profile removes it while its configs answer, then the stack goes.
    """
    cf = ctx.client("cloudformation")
    gs = ctx.client("groundstation")
    stack = ctx.unique_name("sim2real-gsmp-")
    names = (ctx.unique_name("sim2real-gsmp-ep-"), ctx.unique_name("sim2real-gsmp-tracking-"),
             ctx.unique_name("sim2real-gsmp-antenna-"), ctx.unique_name("sim2real-gsmp-dfe-"),
             ctx.unique_name("sim2real-gsmp-mp-"), ctx.unique_name("sim2real-gsmp-role-"))
    endpoint_name, tracking_name, antenna_name, dfe_name, mp_name, role_name = names

    stack_id = create_stack(ctx, cf, stack, _template(names),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    out = stack_outputs(cf, stack_id)
    want_tags = {"sim2real": stack, "sim2real-gs": mp_name}

    # Refs against independent reads: list entries by declared name, or by the run's tag.
    configs = {c["name"]: (c["configArn"], c["configId"], c["configType"])
               for c in paginate(gs, "list_configs", "configList")
               if c["name"] in (tracking_name, antenna_name, dfe_name)}
    assert {n: c[0] for n, c in configs.items()} == {
        tracking_name: out["TrackingArn"], antenna_name: out["AntennaArn"],
        dfe_name: out["DfeArn"]}, f"listed configs {configs!r}"
    want_data = {
        tracking_name: {"trackingConfig": {"autotrack": "PREFERRED"}},
        antenna_name: {"antennaDownlinkConfig": {"spectrumConfig": {
            "centerFrequency": {"value": _CENTER_FREQUENCY_MHZ, "units": "MHz"},
            "bandwidth": {"value": _BANDWIDTH_MHZ, "units": "MHz"},
            "polarization": "NONE",
        }}},
        dfe_name: {"dataflowEndpointConfig": {"dataflowEndpointName": endpoint_name}},
    }
    for name, (_, config_id, config_type) in configs.items():
        data = gs.get_config(configId=config_id, configType=config_type)["configData"]
        if config_type == "dataflow-endpoint":
            data = {"dataflowEndpointConfig": {
                "dataflowEndpointName": data["dataflowEndpointConfig"]["dataflowEndpointName"]}}
        assert data == want_data[name], f"config {name!r} configData {data!r}"

    groups = [
        (g["dataflowEndpointGroupId"], g["dataflowEndpointGroupArn"])
        for g in paginate(gs, "list_dataflow_endpoint_groups", "dataflowEndpointGroupList")
        if gs.list_tags_for_resource(resourceArn=g["dataflowEndpointGroupArn"])["tags"].get(
            "sim2real-gs") == mp_name
    ]
    assert groups == [(out["GroupRef"], out["GroupArn"])], (
        f"listed groups tagged for this run {groups!r}, Ref {out['GroupRef']!r}"
    )
    assert out["GroupId"] == out["GroupRef"], f"GetAtt Id {out['GroupId']!r} != Ref"
    group = gs.get_dataflow_endpoint_group(dataflowEndpointGroupId=groups[0][0])
    got = [(e["endpoint"]["name"], e["endpoint"]["address"], e["endpoint"].get("mtu"),
            e["securityDetails"]["subnetIds"], e["securityDetails"]["securityGroupIds"],
            e["securityDetails"]["roleArn"]) for e in group["endpointsDetails"]]
    assert got == [(endpoint_name, {"name": _ADDRESS, "port": _PORT}, 1500, [out["SubnetId"]],
                    [out["SgId"]], f"arn:{partition}:iam::{ctx.account}:role/{role_name}")], (
        f"group endpoints {got!r}"
    )
    assert (group["contactPrePassDurationSeconds"], group["contactPostPassDurationSeconds"]) == (
        _PRE_PASS_S, _POST_PASS_S), f"group pre/post pass seconds {group!r}"
    group_tags = {k: v for k, v in group["tags"].items() if not k.startswith("aws:")}
    assert group_tags == want_tags, f"group tags {group_tags!r}"

    profiles = [(m["missionProfileId"], m["missionProfileArn"], m["region"])
                for m in paginate(gs, "list_mission_profiles", "missionProfileList")
                if m["name"] == mp_name]
    assert profiles == [(out["MpId"], out["MpArn"], ctx.region)], (
        f"listed mission profiles {profiles!r}, GetAtt Id {out['MpId']!r} Arn {out['MpArn']!r}"
    )
    assert (out["MpRef"], out["MpRegion"]) == (f"{out['MpId']}|{out['MpArn']}", ctx.region), (
        f"MissionProfile Ref {out['MpRef']!r}, GetAtt Region {out['MpRegion']!r}"
    )
    mp = gs.get_mission_profile(missionProfileId=profiles[0][0])
    got = (mp["name"], mp["trackingConfigArn"], mp["minimumViableContactDurationSeconds"],
           mp["dataflowEdges"])
    assert got == (mp_name, out["TrackingArn"], _MIN_CONTACT_S,
                   [[out["AntennaArn"], out["DfeArn"]]]), f"mission profile {got!r}"
    mp_tags = {k: v for k, v in mp["tags"].items() if not k.startswith("aws:")}
    assert mp_tags == want_tags, f"mission profile tags {mp_tags!r}"

    # Child before parent: the update drops only the profile while its configs and group answer.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(names, with_profile=False),
                    Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"profile-removing update ended {status!r}"
    tracking = gs.get_config(configId=configs[tracking_name][1], configType="tracking")
    assert tracking["configArn"] == out["TrackingArn"], f"tracking config {tracking!r}"
    mp_gone = ("ResourceNotFoundException", "MissionProfile not found")
    expect_error(lambda: gs.get_mission_profile(missionProfileId=out["MpId"]), *mp_gone)

    delete_stack(cf, stack_id)
    group_gone = ("ResourceNotFoundException", "The specified group does not exist.")
    expect_error(
        lambda: gs.get_dataflow_endpoint_group(dataflowEndpointGroupId=out["GroupId"]), *group_gone
    )
    for config_id, config_type in [c[1:] for c in configs.values()]:
        config_gone = (
            "ResourceNotFoundException", f"No config found with id {config_id} and type {config_type}"
        )
        expect_error(
            lambda cid=config_id, ctype=config_type: gs.get_config(configId=cid, configType=ctype),
            *config_gone,
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
