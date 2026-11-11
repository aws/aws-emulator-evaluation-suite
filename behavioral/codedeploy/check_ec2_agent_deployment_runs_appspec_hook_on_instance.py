"""ec2-agent-deployment-runs-appspec-hook-on-instance."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "ec2-agent-deployment-runs-appspec-hook-on-instance"
GROUP = 'lifecycle'
SERVICES = ['codedeploy']

TERMINAL = ("Succeeded", "Failed", "Stopped")
INSTANCE_TYPE = "t3.micro"
SENTINEL_PATH = "/opt/sim2real/sentinel"
TAG_KEY = "sim2real-codedeploy-target"
VPC_CIDR = "10.184.0.0/16"
SUBNET_CIDR = "10.184.1.0/24"
# Server-platform revisions are zip bundles, unlike Lambda-platform S3 revisions, which must be
# the bare AppSpec file.
_APPSPEC_YML = """\
version: 0.0
os: linux
files:
  - source: payload.txt
    destination: /opt/sim2real
hooks:
  AfterInstall:
    - location: after_install.sh
      timeout: 60
      runas: root
"""


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """A Server-platform deployment to a tagged EC2 instance running the CodeDeploy agent installs
    the revision's files and runs its AfterInstall hook, read back off the host via SSM, and the
    instance target reports Install and AfterInstall Succeeded.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/userguide/reference-appspec-file.html
    """
    cd = ctx.client("codedeploy")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")

    token = "sim2real-" + ctx.unique_name("")[-12:]
    tag_value = ctx.unique_name("cd-target-")

    bucket = _create_revision_bucket(ctx, s3)
    after_install = (
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "mkdir -p /opt/sim2real\n"
        f"printf '%s' {token!r} > {SENTINEL_PATH}\n"
    )
    bundle = _make_revision_zip({
        "appspec.yml": _APPSPEC_YML,
        "payload.txt": "sim2real codedeploy revision payload\n",
        "after_install.sh": after_install,
    })
    s3.put_object(Bucket=bucket, Key="revision.zip", Body=bundle)
    etag = s3.head_object(Bucket=bucket, Key="revision.zip")["ETag"].strip('"')

    profile_name, _ = _create_instance_profile(ctx, bucket)
    az, subnet_id = _create_network(ctx, ec2)
    instance_id = _launch_agent_instance(ctx, ec2, subnet_id, profile_name,
                                         TAG_KEY, tag_value)
    _wait_ssm_online(ctx, ssm, instance_id)
    active = _wait_agent_active(ctx, ssm, instance_id)
    assert active == "active", (
        f"the CodeDeploy agent on {instance_id!r} in {az!r} reports {active!r}; the host is "
        f"provisioned but the agent is not running, so no deployment can reach it"
    )

    app = _create_application(ctx, compute_platform="Server")
    dg = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.AllAtOnce",
        deploymentStyle={"deploymentType": "IN_PLACE",
                         "deploymentOption": "WITHOUT_TRAFFIC_CONTROL"},
        ec2TagFilters=[{"Key": TAG_KEY, "Value": tag_value, "Type": "KEY_AND_VALUE"}])

    dep_id, info = _deploy_and_wait(
        ctx, cd, app, dg,
        {"revisionType": "S3",
         "s3Location": {"bucket": bucket, "key": "revision.zip", "bundleType": "zip",
                        "eTag": etag}},
        timeout_s=900)
    assert info.get("status") == "Succeeded", (
        f"the agent deployment {dep_id!r} ended {info.get('status')!r} with "
        f"errorInformation {info.get('errorInformation')!r}"
    )

    # The hook ran as root on the host.
    contents = _run_command(ctx, ssm, instance_id, [f"cat {SENTINEL_PATH}"], timeout_s=180)
    assert contents.strip() == token, (
        f"the file the AppSpec's AfterInstall hook wrote at {SENTINEL_PATH} contains "
        f"{contents.strip()!r}, expected the token this run generated ({token!r}). The "
        f"deployment reported Succeeded, so either the revision was never unpacked on the "
        f"host or the hook never ran"
    )
    installed = _run_command(ctx, ssm, instance_id,
                             ["cat /opt/sim2real/payload.txt"], timeout_s=180)
    assert "sim2real codedeploy revision payload" in installed, (
        f"the revision's files section must copy payload.txt to /opt/sim2real; the host "
        f"reads {installed.strip()!r}"
    )

    # The control plane agrees about which host, and which hook.
    target = _instance_target(cd, dep_id, instance_id)
    assert target.get("status") == "Succeeded", (
        f"the deployment target for {instance_id!r} reports {target.get('status')!r}, "
        f"expected 'Succeeded'; the target detail is {target!r}"
    )
    events = {e.get("lifecycleEventName"): e.get("status")
              for e in target.get("lifecycleEvents", [])}
    assert events.get("AfterInstall") == "Succeeded", (
        f"the AfterInstall lifecycle event reads {events.get('AfterInstall')!r}; the "
        f"events recorded for the instance were {events!r}, so the AppSpec hook never ran"
    )
    assert events.get("Install") == "Succeeded", (
        f"the Install lifecycle event reads {events.get('Install')!r}; events were "
        f"{events!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=420, **extra):
    """create_deployment, register its teardown immediately, then poll to a terminal state."""
    dep_id = cd.create_deployment(applicationName=app, deploymentGroupName=dg,
                                  revision=revision, **extra)["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
                 lambda i: i.get("status") in TERMINAL,
                 timeout_s=_budget_s(ctx, timeout_s), interval_s=2)
    if info.get("status") not in TERMINAL and _budget_spent(ctx):
        raise TimeoutError(f"deployment {dep_id!r} terminal: the run budget ended first; not graded")
    assert info.get("status") in TERMINAL, (
        f"deployment {dep_id!r} never reached a terminal state; last status "
        f"{info.get('status')!r} with errorInformation {info.get('errorInformation')!r}"
    )
    return dep_id, info


def _list_group_deployments(cd, app, dg):
    """Every deployment id for the group, paginated."""
    ids, token = [], None
    while True:
        kwargs = {"applicationName": app, "deploymentGroupName": dg}
        if token:
            kwargs["nextToken"] = token
        resp = cd.list_deployments(**kwargs)
        ids.extend(resp.get("deployments") or [])
        token = resp.get("nextToken")
        if not token:
            break
    return ids


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _make_codedeploy_role(ctx, prefix, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codedeploy.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )

    def _del_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codedeploy-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return resp["Role"]["Arn"]


def _create_service_role(ctx):
    cached = getattr(ctx, "_cd_service_role_arn", None)
    if cached:
        return cached
    arn = _make_codedeploy_role(ctx, "sim2real-behav-role-codedeploy-",
                                [{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    ctx._cd_service_role_arn = arn
    return arn


def _create_deployment_group(ctx, app, *, deployment_config, name=None, **extra):
    cd = ctx.client("codedeploy")
    name = name or ctx.unique_name("sim2real-behav-cd-dg-")
    kwargs = {
        "applicationName": app,
        "deploymentGroupName": name,
        "deploymentConfigName": deployment_config,
        "serviceRoleArn": extra.pop("serviceRoleArn", None) or _create_service_role(ctx),
        "deploymentStyle": {
            "deploymentType": "BLUE_GREEN",
            "deploymentOption": "WITH_TRAFFIC_CONTROL",
        },
    }
    kwargs.update(extra)
    deadline = time.monotonic() + _budget_s(ctx, 75)
    while True:
        try:
            cd.create_deployment_group(**kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") == "InvalidRoleException" and (
                "assume" in msg or "not authorized" in msg or "permissions required" in msg
            )
            if transient and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if transient and _budget_spent(ctx):
                raise TimeoutError("CreateDeploymentGroup past the service role's propagation: the run budget ended first; not graded") from exc
            raise
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name)
    )
    return name


def _register_deployment_teardown(ctx, cd, dep_id):
    """Drive the deployment to a terminal state at teardown: a non-terminal deployment
    blocks its deployment group's deletion, so this must run before the group's own
    cleanup (LIFO gives that ordering for free)."""
    def _teardown():
        try:
            cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("DeploymentAlreadyCompletedException",
                            "InvalidDeploymentStatusException"):
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get("status")
            if status in TERMINAL:
                return
            time.sleep(2)
        raise AssertionError(
            f"deployment {dep_id} did not reach a terminal state within the teardown "
            "deadline; the deployment group may block deletion"
        )

    ctx.on_cleanup(_teardown)


def _make_revision_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members.items():
            info = zipfile.ZipInfo(name)
            # 0o755 so the agent can execute the hook script it unpacks.
            info.external_attr = (0o755 if name.endswith(".sh") else 0o644) << 16
            zf.writestr(info, body)
    return buf.getvalue()


def _create_instance_profile(ctx, bucket):
    """A role the instance assumes: SSM (so the check can read the host back) plus read on
    the revision bucket (so the agent can fetch the revision)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-ec2-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    managed = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

    def _del_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=managed)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="revision-read",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }, {
                # The agent's installer is fetched from the regional CodeDeploy bucket.
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::aws-codedeploy-*/*",
            }],
        }),
    )
    profile_name = ctx.unique_name("sim2real-behav-cd-prof-")
    iam.create_instance_profile(InstanceProfileName=profile_name, Path="/sim2real/")

    def _del_profile():
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name,
                                                  RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_instance_profile(InstanceProfileName=profile_name)

    ctx.on_cleanup(_del_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    return profile_name, role["Role"]["Arn"]


def _create_network(ctx, ec2):
    """A VPC with one public subnet; the account may have no default VPC.

    Egress is required: the agent installs from the regional CodeDeploy bucket and long-polls.
    """
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert zones, (
        f"no available availability zone in {ctx.region!r} offers {INSTANCE_TYPE!r}; the "
        f"offerings reported were {sorted(offered)!r}, so the fleet this check needs cannot be "
        f"launched here"
    )
    az = zones[0]
    rtags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]
    # The network deletes share one deadline, started by the first of them to run: the terminated
    # instance releases its ENI asynchronously, so DependencyViolation is retried until then.
    net_deadline = []

    def _net_step(fn):
        def _run():
            if not net_deadline:
                net_deadline.append(time.monotonic() + _NET_TEARDOWN_S)
            _try_until(fn, net_deadline[0])
        return _run

    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": rtags}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_net_step(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": rtags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(_net_step(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": rtags}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(_net_step(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(_net_step(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ))
    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": rtags}]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(_net_step(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    ec2.create_route(
        RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)[
        "AssociationId"
    ]
    ctx.on_cleanup(_net_step(lambda: ec2.disassociate_route_table(AssociationId=assoc_id)))
    return az, subnet_id


# The 900 s cleanup budget also covers the terminate waiter (up to 600 s) that runs ahead of the
# network deletes; an instance's ENI is released 60-90 s after it terminates.
_NET_TEARDOWN_S = 240.0


def _try_until(fn, deadline):
    """Retry one delete while AWS still reports a dependency detaching, until a shared deadline.
    A terminated instance releases its ENI asynchronously, so DependencyViolation here is a wait
    rather than a verdict. Not-found (and a gateway already detached) is done; anything else
    raises."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code") or ""
            if "NotFound" in code or code == "Gateway.NotAttached":
                return
            if code in ("DependencyViolation", "InvalidParameterDependency",
                        "DependencyViolation.Group") and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _launch_agent_instance(ctx, ec2, subnet_id, profile_name, tag_key, tag_value):
    ami = _al2023_ami(ctx)
    user_data = (
        "#!/bin/bash\n"
        "set -x\n"
        "dnf install -y ruby wget || yum install -y ruby wget\n"
        f"cd /tmp && wget https://aws-codedeploy-{ctx.region}.s3.{ctx.region}"
        ".amazonaws.com/latest/install\n"
        "chmod +x ./install && ./install auto\n"
        "systemctl enable --now codedeploy-agent\n"
    )
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while True:
        try:
            resp = ec2.run_instances(
                ImageId=ami,
                InstanceType=INSTANCE_TYPE,
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                UserData=user_data,
                # The deployment group selects the host by exactly this tag.
                TagSpecifications=[{
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-cd-i-")},
                             {"Key": tag_key, "Value": tag_value},
                             {"Key": "sim2real:managed", "Value": "true"},
                             {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
                }],
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            unpropagated = err.get("Code") in ("InvalidParameterValue",
                                               "UnauthorizedOperation") and (
                "instance profile" in (err.get("Message") or "").lower()
                or "iam" in (err.get("Message") or "").lower())
            if unpropagated and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if unpropagated and _budget_spent(ctx):
                raise TimeoutError("RunInstances past the instance profile's propagation: the run budget ended first; not graded") from exc
            raise
    instance_id = resp["Instances"][0]["InstanceId"]

    def _terminate():
        ec2.terminate_instances(InstanceIds=[instance_id])
        # Wait past 'shutting-down': the instance holds the ENI, and the instance profile
        # cannot be deleted while it is still attached.
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id],
            WaiterConfig={"Delay": 2, "MaxAttempts": 200})

    ctx.on_cleanup(_terminate)
    return instance_id


def _al2023_ami(ctx):
    """The current AL2023 x86_64 AMI from the public SSM parameter, never a hardcoded id."""
    ssm = ctx.client("ssm")
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), (
        f"the public AL2023 AMI parameter {param!r} returned {value!r}, which is not an "
        f"AMI id"
    )
    return value


def _wait_ssm_online(ctx, ssm, instance_id, timeout_s=420):
    """Poll DescribeInstanceInformation until SSM reports the instance; fail if it never does."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        infos = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        last = infos[0] if infos else None
        if last and last.get("PingStatus") == "Online":
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id!r} Online in SSM: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id!r} never came online in SSM within {timeout_s}s; the last "
        f"instance information was {last!r}. The host is provisioned but unreachable, so "
        f"the deployment's effect could not be read even if it succeeded"
    )


def _wait_agent_active(ctx, ssm, instance_id, timeout_s=480):
    """Poll the host until the CodeDeploy agent unit is active.

    SSM reports the instance Online before user-data finishes installing the agent.
    """
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = ""
    while time.monotonic() < deadline:
        inv = _invoke_command(ctx, ssm, instance_id,
                             ["systemctl is-active codedeploy-agent"], timeout_s=120)
        last = (inv.get("StandardOutputContent") or "").strip()
        if last == "active":
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"the CodeDeploy agent on {instance_id!r} active: the run budget ended first; not graded")
    tail = _invoke_command(
        ctx, ssm, instance_id,
        ["tail -n 40 /var/log/cloud-init-output.log 2>&1 || true"], timeout_s=120)
    raise AssertionError(
        f"the CodeDeploy agent on {instance_id!r} never became active within {timeout_s}s; "
        f"'systemctl is-active codedeploy-agent' last returned {last!r}. A host that boots "
        f"but whose agent never registers is provisioned-but-unconnectable, which is a "
        f"failure and not an environment limit. cloud-init tail: "
        f"{(tail.get('StandardOutputContent') or '')[-1500:]!r}"
    )


def _run_command(ctx, ssm, instance_id, commands, timeout_s=180):
    """Run a shell command on the host and return its stdout, failing on a non-Success
    invocation."""
    inv = _invoke_command(ctx, ssm, instance_id, commands, timeout_s=timeout_s)
    assert inv.get("Status") == "Success", (
        f"the command {commands!r} on {instance_id!r} ended {inv.get('Status')!r}: "
        f"stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv.get("StandardOutputContent") or ""


def _invoke_command(ctx, ssm, instance_id, commands, timeout_s=180):
    """Run a shell command and return the raw invocation, whatever its exit status.

    Retries only InvalidInstanceId while SSM finishes registering the host.
    """
    deadline = time.monotonic() + _budget_s(ctx, 60)
    while True:
        try:
            cmd_id = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands},
            )["Command"]["CommandId"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceId" and \
                    time.monotonic() < deadline:
                time.sleep(2)
                continue
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceId" and \
                    _budget_spent(ctx):
                raise TimeoutError(f"SendCommand to {instance_id!r} past InvalidInstanceId: the run budget ended first; not graded") from exc
            raise
    end = time.monotonic() + _budget_s(ctx, timeout_s)
    inv = None
    while time.monotonic() < end:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvocationDoesNotExist":
                raise
            time.sleep(1)
            continue
        if inv.get("Status") not in ("Pending", "InProgress", "Delayed"):
            break
        time.sleep(1)
    if (inv is None or inv.get("Status") in ("Pending", "InProgress", "Delayed")) and \
            _budget_spent(ctx):
        raise TimeoutError(f"the command {commands!r} on {instance_id!r} finishing: the run budget ended first; not graded")
    assert inv is not None, (
        f"SSM never reported an invocation for {commands!r} on {instance_id!r}"
    )
    assert inv.get("Status") not in ("Pending", "InProgress", "Delayed"), (
        f"the command {commands!r} on {instance_id!r} was still {inv.get('Status')!r} after "
        f"{timeout_s}s"
    )
    return inv


def _instance_target(cd, dep_id, instance_id):
    """The deployment target for one instance, resolved through the paginated target list."""
    target_ids, token = [], None
    while True:
        kwargs = {"deploymentId": dep_id}
        if token:
            kwargs["nextToken"] = token
        resp = cd.list_deployment_targets(**kwargs)
        target_ids.extend(resp.get("targetIds") or [])
        token = resp.get("nextToken")
        if not token:
            break
    assert instance_id in target_ids, (
        f"the deployment's targets are {target_ids!r}, which does not include the tagged "
        f"instance {instance_id!r}; the ec2TagFilters did not select the host"
    )
    target = cd.get_deployment_target(
        deploymentId=dep_id, targetId=instance_id)["deploymentTarget"]
    return target.get("instanceTarget") or {}


def _create_revision_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-behav-cd-rev-")
    s3.create_bucket(Bucket=name,
                     CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _drop():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents") or []:
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_drop)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real", "Value": CHECK}]})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
