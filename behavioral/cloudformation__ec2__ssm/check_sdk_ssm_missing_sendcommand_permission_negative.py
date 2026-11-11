"""sdk-ssm-missing-sendcommand-permission-negative."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sdk-ssm-missing-sendcommand-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A caller whose identity policy denies ssm:SendCommand gets AccessDeniedException with the exact
    message and no command is recorded for the instance; an unrestricted caller's command on the same
    instance reaches Success and is the only command in its history (positive control)."""
    instance_profile = _ssm_instance_profile(ctx)
    ami_id = _latest_al2023_ami(ctx)
    instance_id = _launch_instance(ctx, ami_id, instance_profile_name=instance_profile, name_suffix="denysend")

    info = _wait_ssm_online(ctx, instance_id, timeout_s=300.0)
    if info is None:
        raise AssertionError(f"instance {instance_id} never registered Online with SSM")

    ssm = ctx.client("ssm")
    baseline = ssm.list_commands(InstanceId=instance_id)["Commands"]
    assert baseline == [], "instance already has command history before the test began"

    denied_ssm, account_id, deny_role = _client_with_deny_policy(ctx, "ssm", ["ssm:SendCommand"])
    _wait_role_policy_effective(lambda: denied_ssm.list_commands(InstanceId=instance_id), timeout_s=90.0)
    code, message = _client_error(
        lambda: denied_ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": ["touch /tmp/should-not-run"]},
            TimeoutSeconds=60,
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException from the denied caller's SendCommand, got {code!r}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{deny_role}/sim2real-check is not authorized to "
        f"perform: ssm:SendCommand on resource: arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id} "
        "with an explicit deny in an identity-based policy"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    after_denied = ssm.list_commands(InstanceId=instance_id)["Commands"]
    assert after_denied == [], "a Command record was created despite AccessDenied on SendCommand"

    # positive control: the unrestricted caller can still send and execute a command
    control = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": ["echo control-ok"]},
        TimeoutSeconds=120,
    )
    result = _poll_invocation(ctx, control["Command"]["CommandId"], instance_id, timeout_s=180.0)
    assert result["Status"] == "Success", f"expected the unrestricted control command to reach Success, got {result['Status']!r}"

    after_control = ssm.list_commands(InstanceId=instance_id)["Commands"]
    assert len(after_control) == 1, f"expected exactly one command in history after the control run, got {len(after_control)}"
    assert after_control[0]["CommandId"] == control["Command"]["CommandId"], (
        f"expected the recorded command id {control['Command']['CommandId']!r}, got {after_control[0]['CommandId']!r}"
    )


def _tag_spec(ctx, resource_type: str, name: str):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]


def _public_subnet(ctx) -> str:
    """A VPC the check owns, with one public subnet routed to an internet gateway, so the instance
    can reach the SSM endpoints. Every piece is torn down in reverse order."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.71.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", ctx.unique_name("sim2real-ssmdeny-vpc-"))
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_tag_spec(ctx, "internet-gateway", ctx.unique_name("sim2real-ssmdeny-igw-"))
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.71.1.0/24",
        TagSpecifications=_tag_spec(ctx, "subnet", ctx.unique_name("sim2real-ssmdeny-subnet-")),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    rtb_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tag_spec(ctx, "route-table", ctx.unique_name("sim2real-ssmdeny-rtb-"))
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb_id))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))
    return subnet_id


def _ssm_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ssm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    )
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            break
        except Exception:
            time.sleep(2.0)
    return profile_name


def _launch_instance(ctx, ami_id: str, instance_profile_name: str | None = None, name_suffix: str = "instance"):
    ec2 = ctx.client("ec2")
    subnet_id = _public_subnet(ctx)
    kwargs = dict(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec(ctx, "instance", ctx.unique_name(f"sim2real-{name_suffix}-")),
    )
    if instance_profile_name:
        kwargs["IamInstanceProfile"] = {"Name": instance_profile_name}
    # A freshly created IAM instance profile can take longer to propagate to the EC2
    # control plane than to IAM itself; retry RunInstances on that specific error.
    deadline = time.monotonic() + 60.0
    resp = None
    while True:
        try:
            resp = ec2.run_instances(**kwargs)
            break
        except Exception as exc:
            if instance_profile_name and "InvalidParameterValue" in str(exc) and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    instance_id = resp["Instances"][0]["InstanceId"]

    def _terminate() -> None:
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    ctx.on_cleanup(_terminate)
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


def _wait_ssm_online(ctx, instance_id: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        items = resp.get("InstanceInformationList", [])
        if items and items[0].get("PingStatus") == "Online":
            return items[0]
        time.sleep(interval_s)
    return None


def _poll_invocation(ctx, command_id: str, instance_id: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    ssm = ctx.client("ssm")
    terminal = {"Success", "Cancelled", "TimedOut", "Failed"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            time.sleep(interval_s)
            continue
        if last["Status"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"command invocation {command_id} on {instance_id} did not reach a terminal state within "
        f"{timeout_s}s; last saw {last!r}"
    )


def _wait_role_policy_effective(allowed_call, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    """The role's inline policy propagates after AssumeRole already works. Poll a call the policy
    ALLOWS until it stops being denied, so the SendCommand refusal comes from the explicit Deny."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            allowed_call()
            return
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last != "AccessDeniedException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"the deny role's inline policy never took effect within {timeout_s}s (last={last!r})")


def _client_with_deny_policy(ctx, service: str, deny_actions: list[str]):
    """Assume a fresh role that allows everything except `deny_actions` (explicit Deny
    always wins over Allow), simulating a caller that lacks those specific permissions."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-deny-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": deny_actions, "Resource": "*"},
        ],
    }
    policy_name = ctx.unique_name("sim2real-deny-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # IAM role propagation is eventually consistent; poll assume-role until it succeeds.
    deadline = time.monotonic() + 30.0
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-check")["Credentials"]
            break
        except ClientError:
            time.sleep(2.0)
    if creds is None:
        raise AssertionError(f"could not assume role {role_arn} in time")

    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, account_id, role_name


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an over-permissive
    target is reported as accepting the call, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected SendCommand to be denied, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
