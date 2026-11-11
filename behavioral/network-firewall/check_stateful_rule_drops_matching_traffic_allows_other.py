"""stateful-rule-drops-matching-traffic-allows-other."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stateful-rule-drops-matching-traffic-allows-other"
GROUP = "data-plane"
SERVICES = ["network-firewall"]

_TARGET_IP = "10.99.2.10"
_VPC_CIDR = "10.99.0.0/16"
_FW_SUBNET_CIDR = "10.99.0.0/24"
_WORKLOAD_SUBNET_CIDR = "10.99.1.0/24"
_TARGET_SUBNET_CIDR = "10.99.2.0/24"


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stateful DROP rule for tcp/8080 to one host blocks that traffic through the firewall
    endpoint while tcp/8081 to the same host passes, as the workload instance reports in its tags;
    it proves the firewall enforces packets, not only API state."""
    ec2 = ctx.client("ec2")
    nfw = ctx.client("network-firewall")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-nfw-dp-")

    # 1. VPC with DNS support (needed for the private EC2 API interface endpoint)
    vpc_id = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    fw_subnet_id = _create_subnet(ctx, ec2, vpc_id, _FW_SUBNET_CIDR, az, name + "-fw")
    workload_subnet_id = _create_subnet(ctx, ec2, vpc_id, _WORKLOAD_SUBNET_CIDR, az, name + "-workload")
    target_subnet_id = _create_subnet(ctx, ec2, vpc_id, _TARGET_SUBNET_CIDR, az, name + "-target")

    # 2. Security groups
    target_sg = ec2.create_security_group(
        GroupName=name + "-target-sg", Description="target", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name + "-target-sg"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=target_sg))
    ec2.authorize_security_group_ingress(
        GroupId=target_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8081,
                         "IpRanges": [{"CidrIp": _VPC_CIDR}]}],
    )

    workload_sg = ec2.create_security_group(
        GroupName=name + "-workload-sg", Description="workload", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name + "-workload-sg"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=workload_sg))

    endpoint_sg = ec2.create_security_group(
        GroupName=name + "-endpoint-sg", Description="ec2-api-endpoint", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name + "-endpoint-sg"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=endpoint_sg))
    ec2.authorize_security_group_ingress(
        GroupId=endpoint_sg,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                         "UserIdGroupPairs": [{"GroupId": workload_sg}]}],
    )

    # 3. Interface VPC endpoint so the workload instance can call ec2:CreateTags without a NAT/IGW
    region = ctx.region
    endpoint_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface", VpcId=vpc_id, ServiceName=f"com.amazonaws.{region}.ec2",
        SubnetIds=[workload_subnet_id], SecurityGroupIds=[endpoint_sg], PrivateDnsEnabled=True,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [{"Key": "Name", "Value": name + "-ec2-endpoint"}]}],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]))
    _wait_for_vpc_endpoint_available(ec2, endpoint_id, timeout_s=300)

    # 4. Stateful rule group: DROP tcp/8080 to the target's fixed IP; everything else passes
    rule_group_name = ctx.unique_name("sim2real-nfw-dp-rg-")
    rg_resp = nfw.create_rule_group(
        RuleGroupName=rule_group_name, Type="STATEFUL", Capacity=100,
        RuleGroup={"RulesSource": {"StatefulRules": [{
            "Action": "DROP",
            "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                       "Direction": "FORWARD", "Destination": f"{_TARGET_IP}/32", "DestinationPort": "8080"},
            "RuleOptions": [{"Keyword": "sid:1"}],
        }]}},
    )
    rule_group_arn = rg_resp["RuleGroupResponse"]["RuleGroupArn"]
    ctx.on_cleanup(lambda: nfw.delete_rule_group(RuleGroupArn=rule_group_arn))

    policy_name = ctx.unique_name("sim2real-nfw-dp-policy-")
    policy_resp = nfw.create_firewall_policy(
        FirewallPolicyName=policy_name,
        FirewallPolicy={
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
            "StatefulRuleGroupReferences": [{"ResourceArn": rule_group_arn}],
        },
    )
    policy_arn = policy_resp["FirewallPolicyResponse"]["FirewallPolicyArn"]
    ctx.on_cleanup(lambda: nfw.delete_firewall_policy(FirewallPolicyArn=policy_arn))

    fw_resp = nfw.create_firewall(
        FirewallName=name, FirewallPolicyArn=policy_arn, VpcId=vpc_id,
        SubnetMappings=[{"SubnetId": fw_subnet_id}],
        DeleteProtection=False, SubnetChangeProtection=False, FirewallPolicyChangeProtection=False,
    )
    firewall_arn = fw_resp["Firewall"]["FirewallArn"]
    ctx.on_cleanup(lambda: _delete_firewall_and_wait(nfw, firewall_arn))

    _wait_for_ready(nfw, firewall_arn, timeout_s=900)
    endpoint_id_fw = nfw.describe_firewall(FirewallArn=firewall_arn)["FirewallStatus"]["SyncStates"][az]["Attachment"]["EndpointId"]

    # 5. Route inter-subnet traffic through the firewall endpoint (more-specific than the /16 local route)
    workload_rt = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=workload_rt))
    assoc1 = ec2.associate_route_table(RouteTableId=workload_rt, SubnetId=workload_subnet_id)["AssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc1))
    ec2.create_route(RouteTableId=workload_rt, DestinationCidrBlock=_TARGET_SUBNET_CIDR, VpcEndpointId=endpoint_id_fw)

    target_rt = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=target_rt))
    assoc2 = ec2.associate_route_table(RouteTableId=target_rt, SubnetId=target_subnet_id)["AssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc2))
    ec2.create_route(RouteTableId=target_rt, DestinationCidrBlock=_WORKLOAD_SUBNET_CIDR, VpcEndpointId=endpoint_id_fw)

    # 6. IAM role so the workload instance can tag itself with the observed result
    role_name = ctx.unique_name("sim2real-nfw-dp-role-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="tag-self", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:CreateTags", "Resource": "*"}],
    }))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="tag-self"))
    profile_name = ctx.unique_name("sim2real-nfw-dp-prof-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))

    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]

    target_user_data = """#!/bin/bash
cat > /tmp/listener.py << 'PYEOF'
import socket, threading, time

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    while True:
        conn, _ = s.accept()
        try:
            conn.sendall(b"ok\\n")
        finally:
            conn.close()

for p in (8080, 8081):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
while True:
    time.sleep(3600)
PYEOF
nohup python3 /tmp/listener.py > /tmp/listener.log 2>&1 &
"""

    target_id = _run_instance(
        ec2, ami_id, target_subnet_id, [target_sg], name + "-target",
        user_data=target_user_data, private_ip=_TARGET_IP,
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, target_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[target_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    workload_user_data = f"""#!/bin/bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)

check_port() {{
  python3 - "$1" "$2" << 'PYEOF'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((host, port), timeout=8)
    s.close()
    print("ALLOWED")
except Exception:
    print("BLOCKED")
PYEOF
}}

# tcp/8081 is unfiltered, so it doubles as the readiness gate for the target's
# cloud-init-started listeners: retry it (bounded) instead of guessing a fixed
# boot delay, then take a single reading of the firewalled port.
wait_for_port() {{
  local host="$1" port="$2" deadline=$(( $(date +%s) + 120 ))
  local result="BLOCKED"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    result=$(check_port "$host" "$port")
    if [ "$result" = "ALLOWED" ]; then
      break
    fi
    sleep 5
  done
  echo "$result"
}}

R8081=$(wait_for_port "{_TARGET_IP}" 8081)
R8080=$(check_port "{_TARGET_IP}" 8080)

aws ec2 create-tags --region "$REGION" --resources "$IID" \
  --tags "Key=sim2real:port8080,Value=$R8080" "Key=sim2real:port8081,Value=$R8081" "Key=sim2real:ready,Value=1"
"""

    workload_id = _run_instance(
        ec2, ami_id, workload_subnet_id, [workload_sg], name + "-workload",
        user_data=workload_user_data, iam_profile=profile_name,
    )
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, workload_id))
    ec2.get_waiter("instance_running").wait(InstanceIds=[workload_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    tags = _poll_for_tag(ec2, workload_id, "sim2real:ready", timeout_s=300)
    assert tags.get("sim2real:ready") == "1", f"expected workload instance to report ready, got {tags.get('sim2real:ready')!r}"
    assert tags.get("sim2real:port8080") == "BLOCKED", f"expected DROP rule to block tcp/8080, got {tags.get('sim2real:port8080')}"
    assert tags.get("sim2real:port8081") == "ALLOWED", f"expected unrelated tcp/8081 to pass, got {tags.get('sim2real:port8081')}"


def _create_subnet(ctx, ec2, vpc_id, cidr, az, tag_name):
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id


def _retry_dependency(fn, timeout_s=180, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "DependencyViolation" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _wait_for_vpc_endpoint_available(ec2, endpoint_id, timeout_s=300):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        eps = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
        state = eps[0]["State"]
        if state == "available":
            return
        time.sleep(2)
    raise AssertionError(f"VPC endpoint never became available, last state={state}")


def _wait_for_ready(nfw, firewall_arn, timeout_s=900):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = nfw.describe_firewall(FirewallArn=firewall_arn)["FirewallStatus"]["Status"]
        if status == "READY":
            return
        assert status != "FAILED", "firewall entered FAILED state"
        time.sleep(2)
    raise AssertionError(f"firewall never reached READY, last status={status}")


def _delete_firewall_and_wait(nfw, firewall_arn, timeout_s=450):
    try:
        nfw.update_firewall_delete_protection(FirewallArn=firewall_arn, DeleteProtection=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        nfw.delete_firewall(FirewallArn=firewall_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            nfw.describe_firewall(FirewallArn=firewall_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(10)


def _run_instance(ec2, ami_id, subnet_id, sg_ids, tag_name, user_data, private_ip=None, iam_profile=None):
    network_interface = {
        "DeviceIndex": 0, "SubnetId": subnet_id, "Groups": sg_ids, "AssociatePublicIpAddress": False,
    }
    if private_ip:
        network_interface["PrivateIpAddress"] = private_ip
    kwargs = dict(
        ImageId=ami_id, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        NetworkInterfaces=[network_interface],
        UserData=base64.b64encode(user_data.encode()).decode(),
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )
    if iam_profile:
        kwargs["IamInstanceProfile"] = {"Name": iam_profile}
    deadline = time.monotonic() + 90
    while True:
        try:
            resp = ec2.run_instances(**kwargs)
            return resp["Instances"][0]["InstanceId"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValue" and "Invalid IAM Instance Profile" in str(e) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _terminate_and_wait(ec2, instance_id):
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _poll_for_tag(ec2, instance_id, tag_key, timeout_s=300, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        tags = {t["Key"]: t["Value"] for t in resp["Reservations"][0]["Instances"][0].get("Tags", [])}
        if tag_key in tags:
            return tags
        time.sleep(interval_s)
    raise AssertionError(f"instance never reported tag {tag_key} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
