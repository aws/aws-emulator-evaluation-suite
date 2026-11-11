"""deploy-vpclattice-gateway-configuration-and-associations-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-vpclattice-gateway-configuration-and-associations-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2", "vpc-lattice"]

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

_VPC_CIDR = "10.120.0.0/16"
_SUBNET_CIDR = "10.120.0.0/24"
# In the VPC but outside its one subnet: no network interface (the resource gateway's or the VPC
# association's) can hold it, so the resource association never finds the IP in use.
_IP_RESOURCE = "10.120.1.50"
_PORT_RANGE = "443"


def _template(tag_value: str, az: str, names: dict[str, str], associations: bool = True) -> str:
    """The network, gateway and configuration, plus both service network associations."""
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                                "AvailabilityZone": az, "Tags": t},
            },
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"GroupDescription": "sim2real vpc lattice resource gateway sg",
                                "VpcId": {"Ref": "Vpc"}, "Tags": t},
            },
            "ServiceNetwork": {
                "Type": "AWS::VpcLattice::ServiceNetwork",
                "Properties": {"Name": names["service_network"], "Tags": t},
            },
            "ResourceGateway": {
                "Type": "AWS::VpcLattice::ResourceGateway",
                "Properties": {
                    "Name": names["resource_gateway"],
                    "VpcIdentifier": {"Ref": "Vpc"},
                    "SubnetIds": [{"Ref": "Subnet"}],
                    "SecurityGroupIds": [{"Ref": "Sg"}],
                    "Tags": t,
                },
            },
            "ResourceConfiguration": {
                "Type": "AWS::VpcLattice::ResourceConfiguration",
                "Properties": {
                    "Name": names["resource_configuration"],
                    "ResourceConfigurationType": "SINGLE",
                    "ResourceGatewayId": {"Fn::GetAtt": ["ResourceGateway", "Id"]},
                    "ResourceConfigurationDefinition": {"IpResource": _IP_RESOURCE},
                    "PortRanges": [_PORT_RANGE],
                    "Tags": t,
                },
            },
            "SnResourceAssoc": {
                "Type": "AWS::VpcLattice::ServiceNetworkResourceAssociation",
                "Properties": {
                    "ServiceNetworkId": {"Fn::GetAtt": ["ServiceNetwork", "Id"]},
                    "ResourceConfigurationId": {"Fn::GetAtt": ["ResourceConfiguration", "Id"]},
                    "Tags": t,
                },
            },
            "SnVpcAssoc": {
                "Type": "AWS::VpcLattice::ServiceNetworkVpcAssociation",
                "Properties": {
                    "ServiceNetworkIdentifier": {"Fn::GetAtt": ["ServiceNetwork", "Id"]},
                    "VpcIdentifier": {"Ref": "Vpc"},
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "SgId": {"Value": {"Fn::GetAtt": ["Sg", "GroupId"]}},
            "ServiceNetworkRef": {"Value": {"Ref": "ServiceNetwork"}},
            "ServiceNetworkId": {"Value": {"Fn::GetAtt": ["ServiceNetwork", "Id"]}},
            "ServiceNetworkArn": {"Value": {"Fn::GetAtt": ["ServiceNetwork", "Arn"]}},
            "ResourceGatewayRef": {"Value": {"Ref": "ResourceGateway"}},
            "ResourceGatewayId": {"Value": {"Fn::GetAtt": ["ResourceGateway", "Id"]}},
            "ResourceGatewayArn": {"Value": {"Fn::GetAtt": ["ResourceGateway", "Arn"]}},
            "ResourceConfigurationRef": {"Value": {"Ref": "ResourceConfiguration"}},
            "ResourceConfigurationId": {"Value": {"Fn::GetAtt": ["ResourceConfiguration", "Id"]}},
            "ResourceConfigurationArn": {"Value": {"Fn::GetAtt": ["ResourceConfiguration", "Arn"]}},
            "SnResourceAssocRef": {"Value": {"Ref": "SnResourceAssoc"}},
            "SnResourceAssocId": {"Value": {"Fn::GetAtt": ["SnResourceAssoc", "Id"]}},
            "SnVpcAssocRef": {"Value": {"Ref": "SnVpcAssoc"}},
            "SnVpcAssocId": {"Value": {"Fn::GetAtt": ["SnVpcAssoc", "Id"]}},
            "SnVpcAssocStatus": {"Value": {"Fn::GetAtt": ["SnVpcAssoc", "Status"]}},
        },
    }
    if not associations:
        for logical in ("SnResourceAssoc", "SnVpcAssoc"):
            del template["Resources"][logical]
        for key in ("SnResourceAssocRef", "SnResourceAssocId", "SnVpcAssocRef", "SnVpcAssocId",
                    "SnVpcAssocStatus"):
            del template["Outputs"][key]
    return json.dumps(template)


def _usable_az(ec2) -> str:
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A stack's VpcLattice network, gateway, configuration and two associations read back with
    their Ref/GetAtt outputs, properties and tags; an update drops the associations while the
    service network still answers, and the stack delete removes the rest, each gone by id.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-vpclattice-resourcegateway.html
    """
    ec2 = ctx.client("ec2")
    vl = ctx.client("vpc-lattice")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-vpcl-")
    names = {
        "service_network": ctx.unique_name("sim2real-vpcl-sn-"),
        "resource_gateway": ctx.unique_name("sim2real-vpcl-rg-"),
        "resource_configuration": ctx.unique_name("sim2real-vpcl-rc-"),
    }
    az = _usable_az(ec2)

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK, az, names))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    vpc_id = outputs["VpcId"]
    subnet_id = outputs["SubnetId"]
    sg_id = outputs["SgId"]
    sn_ref, sn_id, sn_arn = (outputs["ServiceNetworkRef"], outputs["ServiceNetworkId"],
                             outputs["ServiceNetworkArn"])
    rg_ref, rg_id, rg_arn = (outputs["ResourceGatewayRef"], outputs["ResourceGatewayId"],
                              outputs["ResourceGatewayArn"])
    rc_ref, rc_id, rc_arn = (outputs["ResourceConfigurationRef"], outputs["ResourceConfigurationId"],
                              outputs["ResourceConfigurationArn"])
    sra_ref, sra_id = outputs["SnResourceAssocRef"], outputs["SnResourceAssocId"]
    sva_ref, sva_id, sva_status = (outputs["SnVpcAssocRef"], outputs["SnVpcAssocId"],
                                    outputs["SnVpcAssocStatus"])

    assert rg_ref == rg_arn, f"Ref {rg_ref!r} should equal the ResourceGateway's Arn {rg_arn!r}"
    assert rc_ref == rc_arn, f"Ref {rc_ref!r} should equal the ResourceConfiguration's Arn {rc_arn!r}"
    # Each Ref and GetAtt id against an independent read: VPC Lattice's own lists, by declared
    # name or by the parent the association names.
    for op, name, want in (
        ("list_service_networks", names["service_network"], (sn_id, sn_ref)),
        ("list_resource_gateways", names["resource_gateway"], (rg_id, rg_ref)),
        ("list_resource_configurations", names["resource_configuration"], (rc_id, rc_ref)),
    ):
        listed = [(x["id"], x["arn"]) for x in paginate(vl, op, "items") if x["name"] == name]
        assert listed == [want], f"{op} lists {listed!r} named {name!r}, expected {[want]!r}"
    listed = [(x["id"], x["arn"]) for x in paginate(
        vl, "list_service_network_resource_associations", "items",
        resourceConfigurationIdentifier=rc_id)]
    assert listed == [(sra_id, sra_ref)], (
        f"the resource configuration's associations are {listed!r}, expected "
        f"{[(sra_id, sra_ref)]!r}"
    )
    listed = [(x["id"], x["arn"]) for x in paginate(
        vl, "list_service_network_vpc_associations", "items", vpcIdentifier=vpc_id)]
    assert listed == [(sva_id, sva_ref)], (
        f"the VPC's service network associations are {listed!r}, expected {[(sva_id, sva_ref)]!r}"
    )

    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    assert [v["CidrBlock"] for v in vpcs] == [_VPC_CIDR], (
        f"expected VPC {vpc_id!r} with CidrBlock {_VPC_CIDR!r}, EC2 reports {vpcs!r}"
    )
    subnets = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
    got_subnets = [(s["VpcId"], s["CidrBlock"], s["AvailabilityZone"]) for s in subnets]
    assert got_subnets == [(vpc_id, _SUBNET_CIDR, az)], (
        f"expected subnet {subnet_id!r} in {vpc_id!r} with {_SUBNET_CIDR!r} in {az!r}, EC2 reports "
        f"{got_subnets!r}"
    )
    # The template's tag and the stack's sim2real tag, which CloudFormation propagates.
    for what, logical_id, resource_id in (("VPC", "Vpc", vpc_id), ("subnet", "Subnet", subnet_id),
                                          ("security group", "Sg", sg_id)):
        ec2_tags = {t["Key"]: t["Value"] for t in ec2.describe_tags(
            Filters=[{"Name": "resource-id", "Values": [resource_id]}])["Tags"]}
        want_tags = {"sim2real": stack, "sim2real-check": CHECK,
                     "aws:cloudformation:stack-name": stack,
                     "aws:cloudformation:logical-id": logical_id,
                     "aws:cloudformation:stack-id": stack_id}
        assert ec2_tags == want_tags, f"the {what}'s tags {ec2_tags!r}, expected {want_tags!r}"
    groups = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"]
    got_groups = [(g["VpcId"], g["Description"]) for g in groups]
    assert got_groups == [(vpc_id, "sim2real vpc lattice resource gateway sg")], (
        f"expected security group {sg_id!r} in {vpc_id!r} with the declared description, EC2 "
        f"reports {got_groups!r}"
    )

    sn = vl.get_service_network(serviceNetworkIdentifier=sn_id)
    assert sn["id"] == sn_id, f"expected ServiceNetwork id {sn_id!r}, VPC Lattice reports {sn['id']!r}"
    assert sn["arn"] == sn_ref, f"Ref {sn_ref!r} should equal the ServiceNetwork's arn {sn['arn']!r}"
    assert sn["arn"] == sn_arn, f"GetAtt Arn {sn_arn!r} should equal the ServiceNetwork's arn {sn['arn']!r}"
    assert sn["name"] == names["service_network"], (
        f"expected ServiceNetwork name {names['service_network']!r}, got {sn['name']!r}"
    )

    rg = vl.get_resource_gateway(resourceGatewayIdentifier=rg_id)
    assert rg["id"] == rg_id, f"expected ResourceGateway id {rg_id!r}, VPC Lattice reports {rg['id']!r}"
    assert rg["arn"] == rg_arn, f"expected ResourceGateway arn {rg_arn!r}, VPC Lattice reports {rg['arn']!r}"
    assert rg["name"] == names["resource_gateway"], (
        f"expected ResourceGateway name {names['resource_gateway']!r}, got {rg['name']!r}"
    )
    assert rg["vpcId"] == vpc_id, f"expected ResourceGateway vpcId {vpc_id!r}, got {rg['vpcId']!r}"
    assert rg["subnetIds"] == [subnet_id], (
        f"expected ResourceGateway subnetIds {[subnet_id]!r}, got {rg['subnetIds']!r}"
    )
    assert rg["securityGroupIds"] == [sg_id], (
        f"expected ResourceGateway securityGroupIds {[sg_id]!r}, got {rg['securityGroupIds']!r}"
    )
    assert rg["status"] == "ACTIVE", f"expected ResourceGateway status ACTIVE, got {rg['status']!r}"

    rc = vl.get_resource_configuration(resourceConfigurationIdentifier=rc_id)
    assert rc["id"] == rc_id, f"expected ResourceConfiguration id {rc_id!r}, got {rc['id']!r}"
    assert rc["arn"] == rc_arn, f"expected ResourceConfiguration arn {rc_arn!r}, got {rc['arn']!r}"
    assert rc["name"] == names["resource_configuration"], (
        f"expected ResourceConfiguration name {names['resource_configuration']!r}, got {rc['name']!r}"
    )
    assert rc["resourceGatewayId"] == rg_id, (
        f"expected ResourceConfiguration resourceGatewayId {rg_id!r}, got {rc['resourceGatewayId']!r}"
    )
    assert rc["type"] == "SINGLE", f"expected ResourceConfiguration type SINGLE, got {rc['type']!r}"
    assert rc["portRanges"] == [_PORT_RANGE], (
        f"expected ResourceConfiguration portRanges {[_PORT_RANGE]!r}, got {rc['portRanges']!r}"
    )
    assert rc["resourceConfigurationDefinition"] == {"ipResource": {"ipAddress": _IP_RESOURCE}}, (
        f"expected ResourceConfiguration ipResource {_IP_RESOURCE!r}, got "
        f"{rc['resourceConfigurationDefinition']!r}"
    )
    assert rc["status"] == "ACTIVE", f"expected ResourceConfiguration status ACTIVE, got {rc['status']!r}"

    sra = vl.get_service_network_resource_association(serviceNetworkResourceAssociationIdentifier=sra_id)
    assert sra["id"] == sra_id, f"expected association id {sra_id!r}, got {sra['id']!r}"
    assert sra["arn"] == sra_ref, f"expected Ref {sra_ref!r} to equal arn {sra['arn']!r}"
    assert sra["resourceConfigurationId"] == rc_id, (
        f"expected association resourceConfigurationId {rc_id!r}, got {sra['resourceConfigurationId']!r}"
    )
    assert sra["serviceNetworkId"] == sn_id, (
        f"expected association serviceNetworkId {sn_id!r}, got {sra['serviceNetworkId']!r}"
    )
    assert sra["status"] == "ACTIVE", f"expected association status ACTIVE, got {sra['status']!r}"

    sva = vl.get_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=sva_id)
    assert sva["id"] == sva_id, f"expected VPC association id {sva_id!r}, got {sva['id']!r}"
    assert sva["arn"] == sva_ref, f"expected Ref {sva_ref!r} to equal arn {sva['arn']!r}"
    assert sva["serviceNetworkId"] == sn_id, (
        f"expected VPC association serviceNetworkId {sn_id!r}, got {sva['serviceNetworkId']!r}"
    )
    assert sva["vpcId"] == vpc_id, f"expected VPC association vpcId {vpc_id!r}, got {sva['vpcId']!r}"
    assert sva["status"] == sva_status, (
        f"expected the GetAtt Status output {sva_status!r} to equal the API's status {sva['status']!r}"
    )

    # The template's tag, the stack's sim2real tag and the aws:cloudformation:* tags
    # CloudFormation adds to each resource.
    for what, logical_id, arn in (
        ("ServiceNetwork", "ServiceNetwork", sn_arn),
        ("ResourceGateway", "ResourceGateway", rg_arn),
        ("ResourceConfiguration", "ResourceConfiguration", rc_arn),
        ("ServiceNetworkResourceAssociation", "SnResourceAssoc", sra_ref),
        ("ServiceNetworkVpcAssociation", "SnVpcAssoc", sva_ref),
    ):
        got_tags = vl.list_tags_for_resource(resourceArn=arn)["tags"]
        want_tags = {"sim2real": stack, "sim2real-check": CHECK,
                     "aws:cloudformation:stack-name": stack,
                     "aws:cloudformation:logical-id": logical_id,
                     "aws:cloudformation:stack-id": stack_id}
        assert got_tags == want_tags, (
            f"expected the {what}'s template Tags {want_tags!r}, VPC Lattice reports {got_tags!r}"
        )

    # The associations alone: an update dropping them deletes each while its service network,
    # configuration and VPC still answer.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(CHECK, az, names, False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"association-removing update ended {status!r}"

    def get_sva():
        return vl.get_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=sva_id)

    def get_sra():
        return vl.get_service_network_resource_association(
            serviceNetworkResourceAssociationIdentifier=sra_id)

    until_raises(get_sva)
    sva_gone = ("ResourceNotFoundException", f"Association {sva_id} cannot be found.")
    expect_error(get_sva, *sva_gone)
    until_raises(get_sra)
    sra_gone = (
        "ResourceNotFoundException", f"Service Network Resource Association not found: {sra_id}"
    )
    expect_error(get_sra, *sra_gone)
    sn = vl.get_service_network(serviceNetworkIdentifier=sn_id)
    assert (sn["id"], sn["arn"]) == (sn_id, sn_arn), f"service network after the update {sn!r}"
    listed = [x["id"] for x in paginate(vl, "list_service_network_vpc_associations", "items",
                                        serviceNetworkIdentifier=sn_id)]
    listed += [x["id"] for x in paginate(vl, "list_service_network_resource_associations",
                                         "items", serviceNetworkIdentifier=sn_id)]
    assert listed == [], f"the service network still lists associations {listed!r}"

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    rc_gone = ("ResourceNotFoundException", f"Resource Configuration not found: {rc_id}")
    expect_error(lambda: vl.get_resource_configuration(resourceConfigurationIdentifier=rc_id),
                 *rc_gone)
    rg_gone = ("ResourceNotFoundException", f"Resource not found: {rg_id}")
    expect_error(lambda: vl.get_resource_gateway(resourceGatewayIdentifier=rg_id), *rg_gone)
    sn_gone = ("ResourceNotFoundException", f"ServiceNetwork {sn_id} cannot be found.")
    expect_error(lambda: vl.get_service_network(serviceNetworkIdentifier=sn_id), *sn_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
