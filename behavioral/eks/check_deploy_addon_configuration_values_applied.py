"""deploy-addon-configuration-values-applied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-addon-configuration-values-applied"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Addon configurationValues supplied in a CFN template persist on the addon (DescribeAddon) and
    name a real schema-defined key (DescribeAddonConfiguration), not opaque unvalidated text."""
    net = _create_vpc_with_subnets(ctx)
    cluster_role_arn = _create_cluster_role(ctx)

    eks = ctx.client("eks")
    cluster_name = ctx.unique_name("sim2real-ekscl-")
    _create_cluster(ctx, eks, cluster_name, cluster_role_arn, net["subnet_ids"])

    config_values = {"env": {"ENABLE_PREFIX_DELEGATION": "true"}}
    template = json.dumps(
        {
            "Resources": {
                "Addon": {
                    "Type": "AWS::EKS::Addon",
                    "Properties": {
                        "AddonName": "vpc-cni",
                        "ClusterName": cluster_name,
                        "ConfigurationValues": json.dumps(config_values),
                        "ResolveConflicts": "OVERWRITE",
                    },
                }
            }
        }
    )
    _deploy_cfn_stack(ctx, template, timeout_s=900.0)

    addon = eks.describe_addon(clusterName=cluster_name, addonName="vpc-cni")["addon"]
    applied = json.loads(addon["configurationValues"])
    assert applied.get("env", {}).get("ENABLE_PREFIX_DELEGATION") == "true", (
        f"configurationValues not applied, got {addon['configurationValues']!r}"
    )

    schema_resp = eks.describe_addon_configuration(addonName="vpc-cni", addonVersion=addon["addonVersion"])
    schema = json.loads(schema_resp["configurationSchema"])
    assert _schema_defines_property(schema, "env"), (
        f"the 'env' key we applied is not a schema-defined configuration property, schema={schema!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _schema_defines_property(schema, key):
    """Recursively search a JSON-Schema document for `key` used as a property
    name anywhere (top-level `properties`, nested `properties`, or inside
    `definitions`/`$defs`) -- addon config schemas vary in nesting depth."""
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict) and key in props:
            return True
        for v in schema.values():
            if _schema_defines_property(v, key):
                return True
    elif isinstance(schema, list):
        for item in schema:
            if _schema_defines_property(item, key):
                return True
    return False



def _tagspec_ec2(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}



def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-eksvpc")
    vpc_id = ec2.create_vpc(CidrBlock="10.44.0.0/16", TagSpecifications=[_tagspec_ec2("vpc", tag)])["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.44.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tagspec_ec2("subnet", f"{tag}-{i}")],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        subnet_ids.append(sid)
    igw_id = ec2.create_internet_gateway(TagSpecifications=[_tagspec_ec2("internet-gateway", tag)])[
        "InternetGateway"
    ]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[_tagspec_ec2("route-table", tag)])[
        "RouteTable"
    ]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)

    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))
    for sid in subnet_ids:
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _cluster_status_or_gone(eks, name):
    try:
        return eks.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _delete_cluster_and_wait(eks, name, timeout_s=900.0):
    eks.delete_cluster(name=name)
    _poll_until(
        lambda: _cluster_status_or_gone(eks, name),
        lambda s: s is None,
        timeout_s=timeout_s,
        interval_s=20.0,
    )


def _create_cluster(ctx, eks, name, role_arn, subnet_ids, timeout_s=1200.0):
    deadline = time.monotonic() + 90.0
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, name))
    status = _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"]["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=timeout_s,
        interval_s=20.0,
    )
    if status != "ACTIVE":
        raise AssertionError(f"cluster {name} ended in status {status}")
    return name


def _stack_status(cfn, stack_name):
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return None


def _deploy_cfn_stack(ctx, template_body, timeout_s=900.0):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eks-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        _poll_until(
            lambda: _stack_status(cfn, stack_name),
            lambda s: s is None or s == "DELETE_COMPLETE",
            timeout_s=timeout_s,
            interval_s=15.0,
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"),
        timeout_s=timeout_s,
        interval_s=15.0,
    )
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"stack {stack_name} ended in {status}, expected CREATE_COMPLETE")
    return stack_name


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaks the VPC
# while the check passes, until the account's VPC quota fails later checks. So wait
# (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window, and raise
# a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's 1800 s cleanup budget.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
