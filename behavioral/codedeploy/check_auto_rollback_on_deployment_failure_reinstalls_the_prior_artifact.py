"""auto-rollback-on-deployment-failure-reinstalls-the-prior-artifact."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auto-rollback-on-deployment-failure-reinstalls-the-prior-artifact"
GROUP = "lifecycle"
SERVICES = ["codedeploy"]

TERMINAL = ("Succeeded", "Failed", "Stopped")
INSTANCE_TYPE = "t3.micro"
VPC_CIDR = "10.183.0.0/16"
SUBNET_CIDR = "10.183.1.0/24"
TAG_KEY = "sim2real-codedeploy-target"
DEST = "/opt/sim2real"
PAYLOAD = DEST + "/payload.txt"
ROLLBACK_CREATOR = "codeDeployRollback"
#: How long the rollback has to reach the host after the failed deployment goes terminal.
#: Generous on purpose; the failure message reports the measured value.
ROLLBACK_BOUND_S = 300.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """When revision B installs and then fails ValidateService, the automatic DEPLOYMENT_FAILURE
    rollback Succeeds with revision A and puts A's bytes back in the deployed file on the host: a
    rollback that only exists as a record leaves the broken build running."""
    cd = ctx.client("codedeploy")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")

    marker_a = "sim2real-revA-" + ctx.unique_name("")[-12:]
    marker_b = "sim2real-revB-" + ctx.unique_name("")[-12:]
    tag_value = ctx.unique_name("cd-target-")

    bucket = _create_revision_bucket(ctx, s3)
    rev_a = _put_revision(s3, bucket, "rev-a.zip", _bundle(marker_a, validate_exit=0))
    release = f"/tmp/{marker_b}.release"
    rev_b = _put_revision(
        s3, bucket, "rev-b.zip", _bundle(marker_b, validate_exit=1, hold_until=release)
    )

    profile = _create_instance_profile(ctx, bucket)
    az, subnet_id = _create_network(ctx, ec2)
    instance_id = _launch_agent_instances(
        ctx, ec2, subnet_id, profile, TAG_KEY, tag_value, count=1
    )[0]
    _wait_fleet_ready(ctx, ssm, [instance_id])

    app = _create_application(ctx, compute_platform="Server")
    dg = _create_deployment_group(
        ctx,
        app,
        deployment_config="CodeDeployDefault.AllAtOnce",
        ec2TagFilters=[{"Key": TAG_KEY, "Value": tag_value, "Type": "KEY_AND_VALUE"}],
        autoRollbackConfiguration={"enabled": True, "events": ["DEPLOYMENT_FAILURE"]},
    )
    group_info = cd.get_deployment_group(applicationName=app, deploymentGroupName=dg)[
        "deploymentGroupInfo"
    ]
    arc = group_info.get("autoRollbackConfiguration") or {}
    assert arc.get("enabled") is True and arc.get("events") == ["DEPLOYMENT_FAILURE"], (
        f"the group must record the rollback trigger this check depends on; "
        f"GetDeploymentGroup reports autoRollbackConfiguration {arc!r}, expected enabled True "
        f"with events exactly ['DEPLOYMENT_FAILURE']"
    )

    # --- positive control, FIRST: revision A installs and validates ---
    a_id, a_info = _deploy_and_wait(ctx, cd, app, dg, rev_a)
    assert a_info.get("status") == "Succeeded", (
        f"positive control: revision A's deployment {a_id!r} to {instance_id!r} in {az!r} ended "
        f"{a_info.get('status')!r} with errorInformation {a_info.get('errorInformation')!r}; "
        f"until a revision installs on this host, a rollback cannot be shown to restore one"
    )
    on_host = _payload(ctx, ssm, instance_id)
    assert on_host == marker_a, (
        f"positive control: {PAYLOAD} reads {on_host!r} after revision A succeeded, expected "
        f"{marker_a!r}. The rest of this check compares the host against this value, so it must "
        f"be established, not assumed"
    )

    # --- break exactly one thing: revision B's ValidateService exits 1 ---
    b_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, revision=rev_b
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, b_id)

    # B's bytes must actually reach the disk, or the rollback below restores nothing and the
    # headline assertion would hold vacuously. Install precedes ValidateService, and B's
    # ValidateService holds until the check writes `release`, so the window between the two is
    # one this check owns; this poll IS the assertion that B's bytes landed in it.
    _poll(
        lambda: _payload(ctx, ssm, instance_id),
        lambda v: v == marker_b,
        timeout_s=300,
        interval_s=5,
        what=(
            f"revision B's marker {marker_b!r} to appear in {PAYLOAD} on {instance_id!r}: "
            f"Install runs before ValidateService, so the failing revision's bytes must reach "
            f"the disk before the failure -- if they never do, the rollback assertion below "
            f"would pass against a target that did nothing"
        ),
    )
    _run_command(ctx, ssm, instance_id, [f"touch {release}"])

    b_info = _poll(
        lambda: cd.get_deployment(deploymentId=b_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=600,
        interval_s=5,
        what=f"the failing deployment {b_id!r} to reach a terminal state",
    )
    t_failed = time.monotonic()
    assert b_info.get("status") == "Failed", (
        f"a deployment whose ValidateService script exits 1 must end 'Failed'; {b_id!r} ended "
        f"{b_info.get('status')!r} with errorInformation {b_info.get('errorInformation')!r}"
    )
    b_events = {n: s for n, s, _, _, _ in _events_in_order(_instance_target(cd, b_id, instance_id))}
    assert b_events.get("ValidateService") == "Failed", (
        f"the ValidateService lifecycle event reads {b_events.get('ValidateService')!r} on the "
        f"deployment whose ValidateService script exited 1, expected 'Failed'; the events "
        f"reported were {b_events!r}. The rollback must be attributed to the event that failed"
    )
    assert b_events.get("Install") == "Succeeded", (
        f"Install reads {b_events.get('Install')!r} on the failing deployment, expected "
        f"'Succeeded': the failure is at ValidateService, downstream of Install, and the "
        f"observation above confirmed B's bytes reached the disk. Events: {b_events!r}"
    )

    # --- the rollback CodeDeploy created without being asked ---
    attributed = _poll(
        lambda: cd.get_deployment(deploymentId=b_id)["deploymentInfo"],
        lambda i: bool((i.get("rollbackInfo") or {}).get("rollbackDeploymentId")),
        timeout_s=300,
        interval_s=3,
        what=(
            f"rollbackInfo.rollbackDeploymentId to appear on the failed deployment {b_id!r} -- "
            f"autoRollbackConfiguration names DEPLOYMENT_FAILURE, so a rollback deployment must "
            f"be created and attributed"
        ),
    )
    rollback_id = (attributed.get("rollbackInfo") or {}).get("rollbackDeploymentId")
    assert rollback_id and rollback_id != b_id, (
        f"the rollback must be a DISTINCT deployment; rollbackInfo on {b_id!r} reads "
        f"{attributed.get('rollbackInfo')!r}"
    )
    _register_deployment_teardown(ctx, cd, rollback_id)
    rb = _poll(
        lambda: cd.get_deployment(deploymentId=rollback_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=600,
        interval_s=5,
        what=f"the rollback deployment {rollback_id!r} to reach a terminal state",
    )
    assert rb.get("creator") == ROLLBACK_CREATOR, (
        f"the rollback deployment {rollback_id!r} reports creator {rb.get('creator')!r}, "
        f"expected {ROLLBACK_CREATOR!r}: it must be attributed to the service, not to the "
        f"caller, because the caller never made it"
    )
    assert (rb.get("rollbackInfo") or {}).get("rollbackTriggeringDeploymentId") == b_id, (
        f"the rollback's rollbackInfo.rollbackTriggeringDeploymentId reads "
        f"{(rb.get('rollbackInfo') or {}).get('rollbackTriggeringDeploymentId')!r}, expected "
        f"the failed deployment {b_id!r}; the attribution must point both ways"
    )
    assert rb.get("status") == "Succeeded", (
        f"the rollback deployment {rollback_id!r} itself ended {rb.get('status')!r} with "
        f"errorInformation {rb.get('errorInformation')!r}; a rollback that cannot complete has "
        f"left the host on the failed revision"
    )
    rb_etag = ((rb.get("revision") or {}).get("s3Location") or {}).get("eTag")
    a_etag = rev_a["s3Location"]["eTag"]
    assert rb_etag == a_etag, (
        f"the rollback deployment records the S3 revision with eTag {rb_etag!r}; it must "
        f"re-deploy revision A ({a_etag!r}), the last revision that succeeded, and not revision "
        f"B ({rev_b['s3Location']['eTag']!r}) nor some third thing. Full revision: "
        f"{rb.get('revision')!r}"
    )

    # --- THE terminal assertion: the artifact on the host, not the status ---
    # The poll waits only for the file to STOP holding revision B -- a deliberately weaker
    # condition than the one asserted next. If the poll's predicate were "== marker_a", the
    # assertion after it could not fail, because the poll raises on timeout: a target that
    # rewrote the file to some third value would slip through as a timeout rather than as the
    # wrong-content failure it is.
    _poll(
        lambda: _payload(ctx, ssm, instance_id),
        lambda v: v != marker_b,
        timeout_s=ROLLBACK_BOUND_S,
        interval_s=5,
        what=(
            f"{PAYLOAD} on {instance_id!r} to stop holding revision B's marker {marker_b!r}. "
            f"CodeDeploy reported the rollback {rollback_id!r} Succeeded and attributed it to "
            f"the failure, so if the file still holds B the record and the host disagree: the "
            f"rollback exists only as a deployment record and the host is still running the "
            f"revision that failed validation"
        ),
    )
    measured = time.monotonic() - t_failed
    restored = _payload(ctx, ssm, instance_id)
    assert restored == marker_a, (
        f"{PAYLOAD} reads {restored!r} {measured:.1f}s after the failing deployment went "
        f"terminal. It must hold revision A's marker {marker_a!r} -- the last revision that "
        f"succeeded -- and not revision B's {marker_b!r} nor any third value. A rollback that "
        f"leaves something else on disk has not restored the prior artifact"
    )
    rb_events = {
        n: s for n, s, _, _, _ in _events_in_order(_instance_target(cd, rollback_id, instance_id))
    }
    assert rb_events.get("Install") == "Succeeded", (
        f"the rollback's Install event reads {rb_events.get('Install')!r}, expected "
        f"'Succeeded': the bytes on the host changed back, so the agent must have run Install "
        f"and the record must say so. Events: {rb_events!r}"
    )


def _bundle(payload_marker, *, validate_exit, hold_until=None):
    """A revision whose payload carries `payload_marker` and whose ValidateService script exits
    with `validate_exit`. With `hold_until`, ValidateService first waits (bounded, inside the
    hook timeout) for that file to exist, which holds the Install-to-ValidateService window open
    until the check has observed the installed payload."""
    appspec = (
        "version: 0.0\n"
        "os: linux\n"
        "files:\n"
        "  - source: payload.txt\n"
        f"    destination: {DEST}\n"
        "hooks:\n"
        "  ValidateService:\n"
        "    - location: validate_service.sh\n"
        "      timeout: 300\n"
        "      runas: root\n"
    )
    hold = ""
    if hold_until:
        hold = f"for _ in $(seq 1 270); do [ -e {hold_until} ] && break; sleep 1; done\n"
    return {
        "appspec.yml": appspec,
        "payload.txt": payload_marker,
        "validate_service.sh": (
            "#!/bin/bash\n"
            "set -uo pipefail\n"
            f"{hold}"
            f"exit {validate_exit}\n"
        ),
    }


def _payload(ctx, ssm, instance_id):
    """The installed payload marker as the host reads it, or '' when the file is absent.

    The empty default is safe here because every caller compares it for EQUALITY against a
    marker minted in this process: '' can never satisfy one, so the default cannot supply the
    value an assertion exists to detect.
    """
    out = _run_command(ctx, ssm, instance_id, [f"cat {PAYLOAD} 2>/dev/null || true"])
    return out.strip()


# ===== helpers =====
#
# Three rules shape the helpers:
#   1. `_create_network` CREATES a VPC / public subnet / IGW / route rather than adopting an
#      ambient default VPC: an account may have none.
#   2. One body and one deadline on every target.
#   3. `_poll` RAISES on timeout instead of returning its last value: a poll that returns
#      its last value lets the caller assert against a non-terminal state.


def _poll(fn, pred, *, timeout_s, interval_s, what):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; the last value observed was "
                f"{val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=600, **extra):
    """create_deployment, register its teardown immediately, then poll to a terminal state.

    Teardown is registered BEFORE the poll so a deployment that hangs is still driven terminal
    at cleanup -- a non-terminal deployment blocks its deployment group's deletion.
    """
    dep_id = cd.create_deployment(
        applicationName=app, deploymentGroupName=dg, revision=revision, **extra
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(
        lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=timeout_s,
        interval_s=5,
        what=f"deployment {dep_id!r} to reach one of {TERMINAL!r}",
    )
    return dep_id, info


def _register_deployment_teardown(ctx, cd, dep_id):
    """Drive the deployment to a terminal state at teardown: a non-terminal deployment blocks
    its deployment group's deletion, so this must run before the group's own cleanup (LIFO
    gives that ordering for free)."""

    def _teardown():
        try:
            cd.stop_deployment(deploymentId=dep_id, autoRollbackEnabled=False)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in (
                "DeploymentAlreadyCompletedException",
                "InvalidDeploymentStatusException",
            ):
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get("status")
            if status in TERMINAL:
                return
            time.sleep(5)
        raise AssertionError(
            f"deployment {dep_id} did not reach a terminal state within the teardown deadline; "
            "the deployment group may block deletion"
        )

    ctx.on_cleanup(_teardown)


def _create_application(ctx, compute_platform="Server"):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-cd-app-")
    cd.create_application(
        applicationName=name,
        computePlatform=compute_platform,
        tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _make_codedeploy_role(ctx, prefix, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codedeploy.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
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
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codedeploy-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation: _create_deployment_group retries InvalidRoleException until the role is usable.
    return resp["Role"]["Arn"]


def _create_service_role(ctx):
    cached = getattr(ctx, "_cd_service_role_arn", None)
    if cached:
        return cached
    arn = _make_codedeploy_role(
        ctx,
        "sim2real-behav-role-codedeploy-",
        [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    )
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
            "deploymentType": "IN_PLACE",
            "deploymentOption": "WITHOUT_TRAFFIC_CONTROL",
        },
    }
    kwargs.update(extra)
    deadline = time.monotonic() + 102
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
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(
        lambda: cd.delete_deployment_group(applicationName=app, deploymentGroupName=name)
    )
    return name


def _make_revision_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in members.items():
            info = zipfile.ZipInfo(name)
            # 0o755 so the agent can execute the hook scripts it unpacks.
            info.external_attr = (0o755 if name.endswith(".sh") else 0o644) << 16
            zf.writestr(info, body)
    return buf.getvalue()


def _create_revision_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-behav-cd-rev-")
    s3.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
    )

    def _drop():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents") or []:
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_drop)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={
            "TagSet": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real", "Value": CHECK},
            ]
        },
    )
    return name


def _put_revision(s3, bucket, key, members):
    """Upload a zip revision and return the S3 revision locator, eTag included."""
    s3.put_object(Bucket=bucket, Key=key, Body=_make_revision_zip(members))
    etag = s3.head_object(Bucket=bucket, Key=key)["ETag"].strip('"')
    return {
        "revisionType": "S3",
        "s3Location": {
            "bucket": bucket,
            "key": key,
            "bundleType": "zip",
            "eTag": etag,
        },
    }


def _create_instance_profile(ctx, bucket):
    """A role the instance assumes: SSM (so the check can read the host back) plus read on the
    revision bucket (so the agent can fetch the revision)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cd-ec2-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    managed = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

    def _del_role():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=managed)
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_del_role)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="revision-read",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [
                            f"arn:aws:s3:::{bucket}",
                            f"arn:aws:s3:::{bucket}/*",
                        ],
                    },
                    {
                        # The agent's installer is fetched from the regional CodeDeploy bucket.
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::aws-codedeploy-*/*",
                    },
                ],
            }
        ),
    )
    profile_name = ctx.unique_name("sim2real-behav-cd-prof-")
    iam.create_instance_profile(InstanceProfileName=profile_name, Path="/sim2real/")

    def _del_profile():
        iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
        iam.delete_instance_profile(InstanceProfileName=profile_name)

    ctx.on_cleanup(_del_profile)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    # IAM propagation: _launch_agent_instance retries RunInstances until the profile is usable.
    return profile_name


def _create_network(ctx, ec2):
    """A VPC with one public subnet, created in-check.

    Not an ambient default VPC: an account may not have one. Egress is REQUIRED, not cosmetic --
    the agent installs itself from the regional CodeDeploy bucket over the network and then
    long-polls CodeDeploy for work.
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


def _al2023_ami(ctx):
    """The current AL2023 x86_64 AMI from the public SSM parameter, never a hardcoded id."""
    ssm = ctx.client("ssm")
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), (
        f"the public AL2023 AMI parameter {param!r} returned {value!r}, which is not an AMI id"
    )
    return value


def _launch_agent_instances(ctx, ec2, subnet_id, profile_name, tag_key, tag_value, count):
    """Launch `count` instances that install the CodeDeploy agent from user-data.

    All `count` are launched in ONE RunInstances call so their provisioning overlaps: the wall
    clock for a fleet is then about the wall clock for one host, which is what keeps a
    multi-host check inside a runner budget.
    """
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
    deadline = time.monotonic() + 132
    while True:
        try:
            resp = ec2.run_instances(
                ImageId=ami,
                InstanceType=INSTANCE_TYPE,
                MinCount=count,
                MaxCount=count,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                UserData=user_data,
                # Tagged at creation, never after: the deployment group selects these hosts
                # by exactly this tag.
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {
                                "Key": "Name",
                                "Value": ctx.unique_name("sim2real-behav-cd-i-"),
                            },
                            {"Key": tag_key, "Value": tag_value},
                            {"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
                        ],
                    }
                ],
            )
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            unpropagated = err.get("Code") in (
                "InvalidParameterValue",
                "UnauthorizedOperation",
            ) and ("instance profile" in msg or "iam" in msg)
            if unpropagated and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ids = [i["InstanceId"] for i in resp["Instances"]]
    assert len(ids) == count, (
        f"RunInstances returned {len(ids)} instances ({ids!r}), expected {count}; the fleet "
        f"size this check derives its expectations from would be wrong"
    )

    def _terminate():
        ec2.terminate_instances(InstanceIds=ids)
        # Wait past 'shutting-down': each instance holds an ENI in the subnet and its instance
        # profile, neither of which can be deleted while attached. A cut-off teardown here
        # leaks a billing instance AND a VPC, so this wait is generous on purpose.
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_terminate)
    return ids


def _wait_fleet_ready(ctx, ssm, instance_ids, *, online_s=600, agent_s=600):
    """Every host reachable through SSM AND running the CodeDeploy agent.

    A host that boots but whose agent never registers is provisioned-but-unconnectable, which
    is a FAILURE and not an environment limit: no deployment can reach it, so the property this
    check exists to assert would be untestable and must not read as a pass.
    """
    deadline = time.monotonic() + online_s
    pending = set(instance_ids)
    last = {}
    while pending and time.monotonic() < deadline:
        infos = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": sorted(pending)}]
        )["InstanceInformationList"]
        for info in infos:
            last[info["InstanceId"]] = info.get("PingStatus")
            if info.get("PingStatus") == "Online":
                pending.discard(info["InstanceId"])
        if pending:
            time.sleep(5)
    assert not pending, (
        f"{sorted(pending)!r} never came online in SSM within {online_s}s (last ping statuses "
        f"{last!r}); the hosts are provisioned but unreachable, so the deployment's effect "
        f"could not be read even if it succeeded"
    )
    deadline = time.monotonic() + agent_s
    pending = set(instance_ids)
    states = {}
    while pending and time.monotonic() < deadline:
        for iid in sorted(pending):
            inv = _invoke_command(
                ctx, ssm, iid, ["systemctl is-active codedeploy-agent"], timeout_s=120
            )
            states[iid] = (inv.get("StandardOutputContent") or "").strip()
            if states[iid] == "active":
                pending.discard(iid)
        if pending:
            time.sleep(2)
    if pending:
        tails = {
            iid: (
                _invoke_command(
                    ctx,
                    ssm,
                    iid,
                    ["tail -n 30 /var/log/cloud-init-output.log 2>&1 || true"],
                    timeout_s=120,
                ).get("StandardOutputContent")
                or ""
            )[-800:]
            for iid in sorted(pending)
        }
        raise AssertionError(
            f"the CodeDeploy agent never became active on {sorted(pending)!r} within "
            f"{agent_s}s; 'systemctl is-active codedeploy-agent' last returned {states!r}. "
            f"cloud-init tails: {tails!r}"
        )


def _run_command(ctx, ssm, instance_id, commands, timeout_s=180):
    """Run a shell command on the host and return stdout, failing on a non-Success invocation."""
    inv = _invoke_command(ctx, ssm, instance_id, commands, timeout_s=timeout_s)
    assert inv.get("Status") == "Success", (
        f"the command {commands!r} on {instance_id!r} ended {inv.get('Status')!r}: "
        f"stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv.get("StandardOutputContent") or ""


def _invoke_command(ctx, ssm, instance_id, commands, timeout_s=180):
    """Run a shell command and return the raw invocation, whatever its exit status. Retries only
    the documented InvalidInstanceId window while SSM finishes registering the host."""
    deadline = time.monotonic() + 90
    while True:
        try:
            cmd_id = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands},
            )["Command"]["CommandId"]
            break
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") == "InvalidInstanceId"
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise
    end = time.monotonic() + timeout_s
    inv = None
    while time.monotonic() < end:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvocationDoesNotExist":
                raise
            time.sleep(3)
            continue
        if inv.get("Status") not in ("Pending", "InProgress", "Delayed"):
            break
        time.sleep(3)
    assert inv is not None, (
        f"SSM never reported an invocation for {commands!r} on {instance_id!r} within "
        f"{timeout_s}s"
    )
    assert inv.get("Status") not in ("Pending", "InProgress", "Delayed"), (
        f"the command {commands!r} on {instance_id!r} was still {inv.get('Status')!r} after "
        f"{timeout_s}s"
    )
    return inv


def _list_deployment_targets(cd, dep_id):
    """Every target id for the deployment, paginated."""
    ids, token = [], None
    while True:
        kwargs = {"deploymentId": dep_id}
        if token:
            kwargs["nextToken"] = token
        resp = cd.list_deployment_targets(**kwargs)
        ids.extend(resp.get("targetIds") or [])
        token = resp.get("nextToken")
        if not token:
            break
    return ids


def _instance_target(cd, dep_id, instance_id):
    """The instanceTarget record for one host, reached through the paginated target list."""
    target_ids = _list_deployment_targets(cd, dep_id)
    assert instance_id in target_ids, (
        f"the targets of deployment {dep_id!r} are {target_ids!r}, which does not include the "
        f"tagged instance {instance_id!r}; the ec2TagFilters did not select the host"
    )
    target = cd.get_deployment_target(deploymentId=dep_id, targetId=instance_id)[
        "deploymentTarget"
    ]
    return target.get("instanceTarget") or {}


def _events_in_order(instance_target):
    """[(name, status, startTime, endTime, diagnostics)] in the order the service returned them.

    Deliberately a LIST, not a dict: the order is the subject of several assertions here, and
    {name: status} discards exactly the information a target returning a canned unordered
    event set would get wrong.
    """
    return [
        (
            e.get("lifecycleEventName"),
            e.get("status"),
            e.get("startTime"),
            e.get("endTime"),
            e.get("diagnostics") or {},
        )
        for e in instance_target.get("lifecycleEvents", [])
    ]


def _is_subsequence(sub, full):
    """True iff `sub` appears in `full` in order (gaps allowed). The documented run order is a
    TOTAL order over the events that can occur; which of them occur depends on the deployment
    type and the hooks declared, so "is a subsequence of the documented order" is the honest
    derivation rule and an exact list literal would not be."""
    it = iter(full)
    return all(any(x == y for y in it) for x in sub)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
