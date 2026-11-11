"""hook-failure-skips-later-lifecycle-events-and-fails-the-target."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hook-failure-skips-later-lifecycle-events-and-fails-the-target"
GROUP = "lifecycle"
SERVICES = ["codedeploy"]

TERMINAL = ("Succeeded", "Failed", "Stopped")
INSTANCE_TYPE = "t3.micro"
VPC_CIDR = "10.181.0.0/16"
SUBNET_CIDR = "10.181.1.0/24"
TAG_KEY = "sim2real-codedeploy-target"
DEST = "/opt/sim2real"
RAN_LOG = DEST + "/ran.log"

#: The scriptable hooks this revision declares, in the order the CodeDeploy User Guide's
#: "Run order of hooks in a deployment -> In-place deployments" section gives them.
DECLARED_HOOKS = ["BeforeInstall", "AfterInstall", "ApplicationStart", "ValidateService"]
#: The events that must be reported Skipped once BeforeInstall fails: everything the documented
#: order places AFTER it. Derived from DECLARED_HOOKS plus the reserved Install event, not typed
#: out independently, so the two cannot drift.
SKIPPED_AFTER = ["Install"] + DECLARED_HOOKS[1:]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A hook script that exits non-zero fails ITS lifecycle event with ScriptFailed diagnostics
    and SKIPS every later one, and the later hooks really do not run (proven on the host): a
    target that labels a hook Skipped while still running it runs work the operator prevented."""
    cd = ctx.client("codedeploy")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")

    ok_marker = "sim2real-ok-" + ctx.unique_name("")[-12:]
    bad_marker = "sim2real-bad-" + ctx.unique_name("")[-12:]
    stderr_token = "sim2real-stderr-" + ctx.unique_name("")[-12:]
    tag_value = ctx.unique_name("cd-target-")

    bucket = _create_revision_bucket(ctx, s3)
    ok_revision = _put_revision(s3, bucket, "ok.zip", _bundle(ok_marker, fail_token=None))
    bad_revision = _put_revision(
        s3, bucket, "bad.zip", _bundle(bad_marker, fail_token=stderr_token)
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
    )

    # --- positive control, FIRST: every declared hook runs, in order, and succeeds ---
    ok_id, ok_info = _deploy_and_wait(ctx, cd, app, dg, ok_revision)
    assert ok_info.get("status") == "Succeeded", (
        f"positive control: the deployment of the passing revision {ok_id!r} ended "
        f"{ok_info.get('status')!r} with errorInformation {ok_info.get('errorInformation')!r} "
        f"on instance {instance_id!r} in {az!r}. Until this leg passes, a Failed deployment on "
        f"the other leg proves nothing about the hook's exit status"
    )
    ok_events = _events_in_order(_instance_target(cd, ok_id, instance_id))
    ok_status = {name: status for name, status, _, _, _ in ok_events}
    for hook in DECLARED_HOOKS:
        assert ok_status.get(hook) == "Succeeded", (
            f"positive control: the {hook!r} lifecycle event reads "
            f"{ok_status.get(hook)!r}, expected 'Succeeded'; the events the service reported "
            f"were {[(n, s) for n, s, _, _, _ in ok_events]!r}"
        )
    ok_ran = _ran_log(ctx, ssm, instance_id)
    assert ok_ran == DECLARED_HOOKS, (
        f"positive control: the hooks that actually executed on {instance_id!r}, in the order "
        f"they appended themselves to {RAN_LOG}, were {ok_ran!r}; the documented in-place run "
        f"order restricted to the hooks this revision declares is {DECLARED_HOOKS!r}"
    )
    installed = _run_command(ctx, ssm, instance_id, [f"cat {DEST}/payload.txt"])
    assert installed.strip() == ok_marker, (
        f"positive control: {DEST}/payload.txt on the host reads {installed.strip()!r}, "
        f"expected the passing revision's marker {ok_marker!r}; the revision never reached the host"
    )

    # --- break exactly one thing: the exit status of the FIRST scriptable hook ---
    _run_command(ctx, ssm, instance_id, [f"rm -f {RAN_LOG}"])
    bad_id, bad_info = _deploy_and_wait(ctx, cd, app, dg, bad_revision)
    assert bad_info.get("status") == "Failed", (
        f"a deployment whose {DECLARED_HOOKS[0]!r} hook exits non-zero must end 'Failed', "
        f"deployment {bad_id!r} ended {bad_info.get('status')!r}; its errorInformation is "
        f"{bad_info.get('errorInformation')!r}"
    )
    bad_target = _instance_target(cd, bad_id, instance_id)
    assert bad_target.get("status") == "Failed", (
        f"the deployment target for {instance_id!r} reads {bad_target.get('status')!r}, "
        f"expected 'Failed'; a per-host script failure must be attributed to the host, not "
        f"only to the deployment. The target detail is {bad_target!r}"
    )
    bad_events = _events_in_order(bad_target)
    names = [n for n, _, _, _, _ in bad_events]
    bad_status = {n: s for n, s, _, _, _ in bad_events}

    # the failed event, and its diagnostics
    failed_name = DECLARED_HOOKS[0]
    assert bad_status.get(failed_name) == "Failed", (
        f"the {failed_name!r} lifecycle event reads {bad_status.get(failed_name)!r} on a "
        f"deployment whose {failed_name} script exited 1, expected 'Failed'. The events "
        f"reported were {[(n, s) for n, s, _, _, _ in bad_events]!r}"
    )
    diag = next(d for n, _, _, _, d in bad_events if n == failed_name)
    assert diag.get("errorCode") == "ScriptFailed", (
        f"the failed {failed_name!r} event's diagnostics.errorCode reads "
        f"{diag.get('errorCode')!r}, expected 'ScriptFailed' -- the model's LifecycleErrorCode "
        f"value for a script that ran and returned non-zero, as distinct from ScriptMissing, "
        f"ScriptNotExecutable, ScriptTimedOut and UnknownError. Full diagnostics: {diag!r}"
    )
    assert "before_install.sh" in (diag.get("scriptName") or ""), (
        f"the failed event's diagnostics.scriptName reads {diag.get('scriptName')!r}, which "
        f"does not name the script that failed ('before_install.sh'). An emulator that reports "
        f"a failure without saying which script produced it gives an operator nothing"
    )
    assert stderr_token in (diag.get("logTail") or ""), (
        f"the failed event's diagnostics.logTail does not contain the token this run's script "
        f"wrote to stderr ({stderr_token!r}); it reads {(diag.get('logTail') or '')[-400:]!r}. "
        f"The token is generated in this process, so a target that returns a canned or empty "
        f"logTail cannot produce it"
    )

    # every later event is Skipped -- the accounting decision, not the deployment's verdict
    for later in SKIPPED_AFTER:
        assert bad_status.get(later) == "Skipped", (
            f"{later!r} follows the failed {failed_name!r} in the documented in-place run "
            f"order, so it must read 'Skipped'; it reads {bad_status.get(later)!r}. The full "
            f"event list was {[(n, s) for n, s, _, _, _ in bad_events]!r}. 'Succeeded' means "
            f"the target ran work it should have prevented; 'Pending' means it never resolved "
            f"the event at all"
        )
    assert _is_subsequence([failed_name] + SKIPPED_AFTER, names), (
        f"the service returned its lifecycle events as {names!r}, in which the failed "
        f"{failed_name!r} does not precede the skipped {SKIPPED_AFTER!r}; the order carries "
        f"the causality and must survive the failure"
    )

    # the later hooks did not RUN -- independent side-channel on the host. The failed hook
    # itself DID run (that is what 'Failed' means, as against 'Skipped') and every hook logs its
    # own name unconditionally before it exits, so the log after a BeforeInstall failure MUST
    # read exactly [failed_name] -- not empty.
    after_ran = _ran_log(ctx, ssm, instance_id)
    assert after_ran == [failed_name], (
        f"{RAN_LOG} on {instance_id!r} records {after_ran!r} after a deployment whose "
        f"{failed_name!r} hook failed; expected exactly {[failed_name]!r} -- the failed hook "
        f"itself must have run (that is what 'Failed' means, as against never having been "
        f"attempted), but none of the hooks reported 'Skipped' ({SKIPPED_AFTER!r}) may appear. "
        f"A target that ran them anyway is telling the operator it prevented work it in fact "
        f"performed"
    )

    # effect absent: Install was skipped, so the failing revision's payload never landed
    still = _run_command(ctx, ssm, instance_id, [f"cat {DEST}/payload.txt"])
    assert still.strip() == ok_marker, (
        f"{DEST}/payload.txt reads {still.strip()!r} after a deployment that failed before "
        f"Install; it must still hold the previous revision's marker {ok_marker!r} and must "
        f"NOT hold the failing revision's {bad_marker!r}. A skipped Install that copied files "
        f"anyway is a partially applied revision"
    )

    # --- restore: the identical passing revision goes through again ---
    _run_command(ctx, ssm, instance_id, [f"rm -f {RAN_LOG}"])
    redo_id, redo_info = _deploy_and_wait(ctx, cd, app, dg, ok_revision)
    assert redo_info.get("status") == "Succeeded", (
        f"restore: re-deploying the identical passing revision after the failure ended "
        f"{redo_info.get('status')!r} on {redo_id!r} (errorInformation="
        f"{redo_info.get('errorInformation')!r}); the refusal above is then not specific to "
        f"the broken script -- the fixture died"
    )
    redo_ran = _ran_log(ctx, ssm, instance_id)
    assert redo_ran == DECLARED_HOOKS, (
        f"restore: the hooks that executed on the re-run were {redo_ran!r}, expected "
        f"{DECLARED_HOOKS!r}; the host is no longer running the full hook sequence"
    )
    redo_events = _events_in_order(_instance_target(cd, redo_id, instance_id))
    redo_status = {n: s for n, s, _, _, _ in redo_events}
    assert all(redo_status.get(h) == "Succeeded" for h in DECLARED_HOOKS), (
        f"restore: the re-run's events read {[(n, s) for n, s, _, _, _ in redo_events]!r}; "
        f"every declared hook must be 'Succeeded' again"
    )


def _bundle(payload_marker, *, fail_token):
    """The revision bundle. Each hook appends its own name to RAN_LOG, so the host records the
    hooks that really executed. `fail_token` makes BeforeInstall write that token to stderr and
    exit 1 -- the ONE thing that differs between the two legs."""
    hooks = "\n".join(
        f"  {h}:\n    - location: {_script(h)}\n      timeout: 120\n      runas: root"
        for h in DECLARED_HOOKS
    )
    appspec = (
        "version: 0.0\n"
        "os: linux\n"
        "files:\n"
        "  - source: payload.txt\n"
        f"    destination: {DEST}\n"
        "hooks:\n" + hooks + "\n"
    )
    members = {"appspec.yml": appspec, "payload.txt": payload_marker}
    for h in DECLARED_HOOKS:
        body = (
            "#!/bin/bash\n"
            "set -uo pipefail\n"
            f"mkdir -p {DEST}\n"
            # $LIFECYCLE_EVENT is the variable the User Guide promises every hook script; using
            # it rather than a literal means the log records what the AGENT said the event was.
            f'printf "%s\\n" "${{LIFECYCLE_EVENT:-MISSING}}" >> {RAN_LOG}\n'
        )
        if fail_token is not None and h == DECLARED_HOOKS[0]:
            body += f'echo "{fail_token}" >&2\nexit 1\n'
        else:
            body += "exit 0\n"
        members[_script(h)] = body
    return members


def _script(hook_name):
    """before_install.sh from BeforeInstall -- derived, so the appspec and the bundle members
    cannot disagree about a filename."""
    out = []
    for i, ch in enumerate(hook_name):
        if ch.isupper() and i:
            out.append("_")
        out.append(ch.lower())
    return "".join(out) + ".sh"


def _ran_log(ctx, ssm, instance_id):
    """The hook names recorded on the host, in execution order. An absent log is [] -- which is
    the value the post-failure assertion demands, so the default cannot mask a real reading."""
    out = _run_command(ctx, ssm, instance_id, [f"cat {RAN_LOG} 2>/dev/null || true"])
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


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
