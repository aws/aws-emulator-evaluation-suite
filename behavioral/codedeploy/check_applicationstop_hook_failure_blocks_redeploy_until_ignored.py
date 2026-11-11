"""applicationstop-hook-failure-blocks-redeploy-until-ignored.
"""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "applicationstop-hook-failure-blocks-redeploy-until-ignored"
GROUP = "lifecycle"
SERVICES = ["codedeploy"]

TERMINAL = ("Succeeded", "Failed", "Stopped")
INSTANCE_TYPE = "t3.micro"
DEST = "/opt/sim2real-cdstop"
PAYLOAD = f"{DEST}/payload.txt"
#: Written by revision B's AfterInstall hook only. Its ABSENCE is how this check proves the
#: failed deployment did no work on the host, independently of any status the service reports.
B_HOOK_MARKER = f"{DEST}/b-after-install-ran"
TAG_KEY = "sim2real-codedeploy-stop-target"
#: The fixed set of in-place lifecycle events that must be Skipped once ApplicationStop fails.
#: DownloadBundle is deliberately absent: it has not been attempted at ApplicationStop time and
#: this check makes no claim about how the service labels an event it never reached.
SKIPPED_AFTER = ["BeforeInstall", "Install", "AfterInstall", "ApplicationStart",
                 "ValidateService"]
_ROLLBACK_CREATOR = "codeDeployRollback"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """A poisoned ApplicationStop hook in the revision already on the host fails the NEXT
    deployment, keeps its bytes off the disk and triggers the rollback; only
    `ignoreApplicationStopFailures` on an otherwise identical deployment installs it."""
    cd = ctx.client("codedeploy")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")

    marker_a = "sim2real-A-" + ctx.unique_name("")[-12:]
    marker_b = "sim2real-B-" + ctx.unique_name("")[-12:]
    stderr_token = "sim2real-stop-fail-" + ctx.unique_name("")[-12:]
    tag_value = ctx.unique_name("cd-stop-target-")
    assert len({marker_a, marker_b, stderr_token}) == 3, (
        f"setup: the three run-scoped tokens collided: "
        f"{(marker_a, marker_b, stderr_token)!r}"
    )

    # --- two revisions: A's ApplicationStop exits 1, B's does not ---
    bucket = _create_revision_bucket(ctx, s3)
    rev_a = _put_revision(s3, bucket, "revision-a.zip", _bundle_a(marker_a, stderr_token))
    rev_b = _put_revision(s3, bucket, "revision-b.zip", _bundle_b(marker_b))

    # --- the host ---
    net = _create_network(ctx, ec2)
    profile_name, _ = _create_instance_profile(ctx, bucket)
    instance_id = _launch_agent_instance(ctx, ec2, net, profile_name,
                                         TAG_KEY, tag_value)
    _wait_ssm_online(ctx, ssm, instance_id)
    active = _wait_agent_active(ctx, ssm, instance_id)
    assert active == "active", (
        f"the CodeDeploy agent on {instance_id!r} in {net['az']!r} reports {active!r}; the host is "
        f"provisioned but the agent is not running, so no deployment can reach it"
    )

    app = _create_application(ctx, compute_platform="Server")
    dg = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.AllAtOnce",
        deploymentStyle={"deploymentType": "IN_PLACE",
                         "deploymentOption": "WITHOUT_TRAFFIC_CONTROL"},
        autoRollbackConfiguration={"enabled": True, "events": ["DEPLOYMENT_FAILURE"]},
        ec2TagFilters=[{"Key": TAG_KEY, "Value": tag_value, "Type": "KEY_AND_VALUE"}])
    group_info = cd.get_deployment_group(
        applicationName=app, deploymentGroupName=dg)["deploymentGroupInfo"]
    assert group_info.get("autoRollbackConfiguration", {}).get("events") == \
        ["DEPLOYMENT_FAILURE"], (
        f"the deployment group echoed autoRollbackConfiguration "
        f"{group_info.get('autoRollbackConfiguration')!r}, expected events "
        f"['DEPLOYMENT_FAILURE']; the rollback assertion below would be unfalsifiable "
        f"without it"
    )

    # --- arm the trap: revision A must deploy cleanly, which makes ITS ApplicationStop the
    # script every later deployment to this host will run ---
    first_id, first = _deploy_and_wait(ctx, cd, app, dg, rev_a, timeout_s=900)
    assert first.get("status") == "Succeeded", (
        f"the first deployment {first_id!r} of revision A ended {first.get('status')!r} with "
        f"errorInformation {first.get('errorInformation')!r}; revision A must be the last "
        f"SUCCESSFUL revision on {instance_id!r} before its ApplicationStop script can run"
    )
    first_events = _event_status(_instance_target(cd, first_id, instance_id))
    assert first_events.get("Install") == "Succeeded", (
        f"the first deployment's Install event reads {first_events.get('Install')!r}; the "
        f"events recorded for {instance_id!r} were {first_events!r}"
    )
    on_host = _run_command(ctx, ssm, instance_id, [f"cat {PAYLOAD}"])
    assert on_host.strip() == marker_a, (
        f"{PAYLOAD} on {instance_id!r} reads {on_host.strip()!r}, expected revision A's "
        f"marker {marker_a!r}; the trap is not armed because A was never installed"
    )

    # --- break exactly one thing: the exit status of the ALREADY-DEPLOYED revision's
    # ApplicationStop. Nothing about revision B is wrong. ---
    bad_id, bad = _deploy_and_wait(ctx, cd, app, dg, rev_b, timeout_s=900,
                                   fileExistsBehavior="OVERWRITE")
    assert bad.get("status") == "Failed", (
        f"deploying revision B over a host whose last successful revision has an "
        f"ApplicationStop script that exits 1 must end 'Failed'; deployment {bad_id!r} ended "
        f"{bad.get('status')!r} with errorInformation {bad.get('errorInformation')!r}. "
        f"'Succeeded' means the service ran the INCOMING revision's ApplicationStop instead "
        f"of the deployed one"
    )
    bad_target = _instance_target(cd, bad_id, instance_id)
    assert bad_target.get("status") == "Failed", (
        f"the deployment target for {instance_id!r} reads {bad_target.get('status')!r}, "
        f"expected 'Failed'; a per-host script failure must be attributed to the host. The "
        f"target detail is {bad_target!r}"
    )
    bad_status = _event_status(bad_target)
    assert bad_status.get("ApplicationStop") == "Failed", (
        f"the ApplicationStop lifecycle event reads {bad_status.get('ApplicationStop')!r}; "
        f"expected 'Failed' because the script the service ran for it -- revision A's -- "
        f"exited 1. The events reported were {bad_status!r}"
    )

    diag = _event_diagnostics(bad_target, "ApplicationStop")
    assert diag.get("errorCode") == "ScriptFailed", (
        f"the failed ApplicationStop event's diagnostics.errorCode reads "
        f"{diag.get('errorCode')!r}, expected 'ScriptFailed' -- the LifecycleErrorCode value "
        f"for a script that ran and returned non-zero, as distinct from ScriptMissing, "
        f"ScriptNotExecutable, ScriptTimedOut and UnknownError. Full diagnostics: {diag!r}"
    )
    assert "application_stop.sh" in (diag.get("scriptName") or ""), (
        f"the failed event's diagnostics.scriptName reads {diag.get('scriptName')!r}, which "
        f"does not name revision A's script ('application_stop.sh'). Naming the INCOMING "
        f"revision's script here would mean the service resolved the hook from the wrong bundle"
    )
    assert stderr_token in (diag.get("logTail") or ""), (
        f"the failed event's diagnostics.logTail does not contain the token revision A's "
        f"ApplicationStop script wrote to stderr ({stderr_token!r}); it reads "
        f"{(diag.get('logTail') or '')[-400:]!r}. The token is minted in this process and "
        f"embedded in a zip, so no canned or empty logTail can produce it"
    )

    for later in SKIPPED_AFTER:
        assert bad_status.get(later) == "Skipped", (
            f"{later!r} follows the failed 'ApplicationStop' in the in-place run order, so it "
            f"must read 'Skipped'; it reads {bad_status.get(later)!r}. The full event list was "
            f"{bad_status!r}. 'Succeeded' means the target ran work it should have prevented"
        )

    # --- the effect is ABSENT on the host: the strongest half of the negative ---
    still_a = _run_command(ctx, ssm, instance_id, [f"cat {PAYLOAD}"])
    assert still_a.strip() == marker_a, (
        f"{PAYLOAD} on {instance_id!r} reads {still_a.strip()!r} after the failed deployment; "
        f"it must still hold revision A's marker {marker_a!r}. Revision B's marker "
        f"({marker_b!r}) means the service reported a failure and installed the revision "
        f"anyway -- the console says rolled back and the host runs the new build"
    )
    b_marker = _run_command(ctx, ssm, instance_id,
                            [f"test -e {B_HOOK_MARKER} && echo PRESENT || echo ABSENT"])
    assert b_marker.strip() == "ABSENT", (
        f"{B_HOOK_MARKER} on {instance_id!r} reads {b_marker.strip()!r}; revision B's "
        f"AfterInstall hook must never have executed, because the deployment stopped at "
        f"ApplicationStop. 'PRESENT' means 'Skipped' did not mean skipped"
    )

    # --- H4: the rollback the caller never asked for ---
    attributed = _poll(
        lambda: cd.get_deployment(deploymentId=bad_id)["deploymentInfo"],
        lambda i: bool((i.get("rollbackInfo") or {}).get("rollbackDeploymentId")),
        timeout_s=300, interval_s=3)
    rollback_id = (attributed.get("rollbackInfo") or {}).get("rollbackDeploymentId")
    assert rollback_id, (
        f"autoRollbackConfiguration names DEPLOYMENT_FAILURE, so the failed deployment "
        f"{bad_id!r} must name the rollback it spawned in rollbackInfo.rollbackDeploymentId; "
        f"it reads {attributed.get('rollbackInfo')!r}"
    )
    _register_deployment_teardown(ctx, cd, rollback_id)
    rollback = cd.get_deployment(deploymentId=rollback_id)["deploymentInfo"]
    assert rollback.get("creator") == _ROLLBACK_CREATOR, (
        f"the rollback deployment {rollback_id!r} must be attributed to "
        f"{_ROLLBACK_CREATOR!r}, not {rollback.get('creator')!r}; a deployment the service "
        f"made on its own initiative is not a user deployment"
    )
    assert (rollback.get("rollbackInfo") or {}).get("rollbackTriggeringDeploymentId") == \
        bad_id, (
        f"the rollback deployment must point back at the deployment that triggered it "
        f"({bad_id!r}); its rollbackInfo reads {rollback.get('rollbackInfo')!r}"
    )
    # The rollback holds the deployment group, so the positive control cannot start until it is
    # terminal -- an observable condition, polled, never a sleep.
    settled = _poll(lambda: cd.get_deployment(deploymentId=rollback_id)["deploymentInfo"],
                    lambda i: i.get("status") in TERMINAL,
                    timeout_s=900, interval_s=5)
    assert settled.get("status") in TERMINAL, (
        f"the rollback deployment {rollback_id!r} never reached a terminal state; it reads "
        f"{settled.get('status')!r}, and a non-terminal deployment blocks the group"
    )

    # --- positive control, same file, one flag: ignoreApplicationStopFailures ---
    good_id, good = _deploy_and_wait(ctx, cd, app, dg, rev_b, timeout_s=900,
                                     ignoreApplicationStopFailures=True,
                                     fileExistsBehavior="OVERWRITE")
    assert good.get("status") == "Succeeded", (
        f"positive control: the SAME revision B, host, group and role with "
        f"ignoreApplicationStopFailures=True must reach 'Succeeded' past the same poisoned "
        f"ApplicationStop; deployment {good_id!r} ended {good.get('status')!r} with "
        f"errorInformation {good.get('errorInformation')!r}. A target that stores the flag "
        f"and ignores it fails exactly here, and so does one that refuses every redeploy"
    )
    good_status = _event_status(_instance_target(cd, good_id, instance_id))
    assert good_status.get("Install") == "Succeeded", (
        f"positive control: the Install event reads {good_status.get('Install')!r}, expected "
        f"'Succeeded' -- the deployment must have got PAST ApplicationStop, not merely been "
        f"labelled Succeeded. Events: {good_status!r}"
    )
    now_b = _run_command(ctx, ssm, instance_id, [f"cat {PAYLOAD}"])
    assert now_b.strip() == marker_b, (
        f"positive control: {PAYLOAD} on {instance_id!r} reads {now_b.strip()!r}, expected "
        f"revision B's marker {marker_b!r}. The flag's whole purpose is to let the blocked "
        f"revision actually reach the disk; a 'Succeeded' that leaves A's bytes in place is "
        f"the same defect wearing a different label"
    )
    ran_b = _run_command(ctx, ssm, instance_id, [f"cat {B_HOOK_MARKER}"])
    assert ran_b.strip() == marker_b, (
        f"positive control: {B_HOOK_MARKER} reads {ran_b.strip()!r}, expected {marker_b!r}; "
        f"revision B's AfterInstall hook must have executed this time"
    )


# ===== helpers =====

#: Revision A's appspec. Its ApplicationStop hook is the poison; everything else is ordinary.
_APPSPEC_A = """\
version: 0.0
os: linux
files:
  - source: payload.txt
    destination: {dest}
hooks:
  ApplicationStop:
    - location: application_stop.sh
      timeout: 60
      runas: root
  AfterInstall:
    - location: after_install.sh
      timeout: 60
      runas: root
"""

#: Revision B's appspec. Its OWN ApplicationStop is fine -- which is the point: the deployment
#: that fails is B's, and nothing about B is broken.
_APPSPEC_B = """\
version: 0.0
os: linux
files:
  - source: payload.txt
    destination: {dest}
hooks:
  ApplicationStop:
    - location: application_stop.sh
      timeout: 60
      runas: root
  AfterInstall:
    - location: after_install.sh
      timeout: 60
      runas: root
"""


def _bundle_a(marker, stderr_token):
    """Revision A: ApplicationStop writes a run-minted token to stderr and exits 1."""
    return _make_revision_zip({
        "appspec.yml": _APPSPEC_A.format(dest=DEST),
        "payload.txt": marker,
        "application_stop.sh": (
            "#!/bin/bash\n"
            f"printf '%s\\n' {stderr_token!r} >&2\n"
            "exit 1\n"
        ),
        "after_install.sh": (
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            f"mkdir -p {DEST}\n"
            f"printf '%s' {marker!r} > {DEST}/a-after-install-ran\n"
        ),
    })


def _bundle_b(marker):
    """Revision B: every hook succeeds. Its AfterInstall marker is the file whose ABSENCE
    proves the blocked deployment did no work on the host."""
    return _make_revision_zip({
        "appspec.yml": _APPSPEC_B.format(dest=DEST),
        "payload.txt": marker,
        "application_stop.sh": "#!/bin/bash\nexit 0\n",
        "after_install.sh": (
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            f"mkdir -p {DEST}\n"
            f"printf '%s' {marker!r} > {B_HOOK_MARKER}\n"
        ),
    })


def _put_revision(s3, bucket, key, body):
    """Upload a bundle and return the S3 revision locator, eTag included so the deployment
    names the exact bytes it is deploying."""
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    etag = s3.head_object(Bucket=bucket, Key=key)["ETag"].strip('"')
    return {"revisionType": "S3",
            "s3Location": {"bucket": bucket, "key": key, "bundleType": "zip", "eTag": etag}}


def _event_status(instance_target):
    return {e.get("lifecycleEventName"): e.get("status")
            for e in instance_target.get("lifecycleEvents", [])}


def _event_diagnostics(instance_target, name):
    for e in instance_target.get("lifecycleEvents", []):
        if e.get("lifecycleEventName") == name:
            return e.get("diagnostics") or {}
    raise AssertionError(
        f"the instance target reports no {name!r} lifecycle event at all; the events present "
        f"are {[e.get('lifecycleEventName') for e in instance_target.get('lifecycleEvents', [])]!r}"
    )


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _deploy_and_wait(ctx, cd, app, dg, revision, *, timeout_s=900, **extra):
    """create_deployment, register its teardown immediately, then poll to a terminal state."""
    dep_id = cd.create_deployment(applicationName=app, deploymentGroupName=dg,
                                  revision=revision, **extra)["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)
    info = _poll(lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
                 lambda i: i.get("status") in TERMINAL,
                 timeout_s=timeout_s, interval_s=5)
    assert info.get("status") in TERMINAL, (
        f"deployment {dep_id!r} never reached a terminal state; last status "
        f"{info.get('status')!r} with errorInformation {info.get('errorInformation')!r}"
    )
    return dep_id, info


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
    # IAM propagation: _create_deployment_group retries InvalidRoleException until the role is usable.
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
    }
    kwargs.update(extra)
    deadline = time.monotonic() + 87
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


def _register_deployment_teardown(ctx, cd, dep_id):
    """Drive the deployment to a terminal state at teardown: a non-terminal deployment blocks
    its deployment group's deletion, so this must run before the group's own cleanup (LIFO
    gives that ordering for free)."""
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
            time.sleep(5)
        raise AssertionError(
            f"deployment {dep_id} did not reach a terminal state within the teardown deadline; "
            "the deployment group may block deletion"
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
    """A role the instance assumes: SSM (so the check can read the host back) plus read on the
    revision bucket (so the agent can fetch the revisions)."""
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
    # IAM propagation: _launch_agent_instance retries RunInstances until the profile is usable.
    return profile_name, role["Role"]["Arn"]


def _create_network(ctx, ec2):
    """A VPC, subnet, internet gateway, route and security group this check CREATES, returning
    the ids to launch into.

    Deliberately not the account's default VPC: an account need not have one, and a shared
    subnet mutated by another workload is a failure with nothing to do with CodeDeploy.
    Egress is required rather than decorative: the agent installs itself from the regional
    CodeDeploy bucket over the network and then polls CodeDeploy for work.

    The AZ is DERIVED by intersecting the instance-type offerings with the zones that are
    actually available: letting AWS choose, or naming a zone, is the same
    capacity gamble, and AZ names are per-account aliases for different physical zones."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}]
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available availability zone in {ctx.region!r} offers {INSTANCE_TYPE!r}; the "
        f"offerings were {sorted(offered)!r}, so this region cannot run the check"
    )
    az = usable[0]
    net_tags = [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-cd-net-")},
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
                {"Key": "sim2real", "Value": CHECK}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.199.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": net_tags}])["Vpc"]["VpcId"]
    net = {"az": az, "vpc_id": vpc_id, "igw_id": None, "subnet_id": None, "sg_id": None}
    # Registered here ONLY as the fallback for a failure before the instance exists. The real
    # teardown is _register_host_and_network_teardown, registered later and so run FIRST -- see
    # the reasoning there for why the ordering is load-bearing rather than incidental.
    ctx.on_cleanup(lambda: _drop_network(ec2, net, time.monotonic() + 120.0))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id],
                                        WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway",
                            "Tags": net_tags}])["InternetGateway"]["InternetGatewayId"]
    net["igw_id"] = igw_id
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.199.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": net_tags}])["Subnet"]["SubnetId"]
    net["subnet_id"] = subnet_id
    ec2.modify_subnet_attribute(SubnetId=subnet_id,
                                MapPublicIpOnLaunch={"Value": True})

    # The VPC's main route table: adding the default route makes the subnet public. The table
    # itself is deleted with the VPC, so it needs no separate teardown.
    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                 {"Name": "association.main", "Values": ["true"]}])["RouteTables"]
    assert tables, (
        f"the VPC {vpc_id!r} this check created reports no main route table; the subnet cannot "
        f"be given a route to the internet gateway"
    )
    ec2.create_route(RouteTableId=tables[0]["RouteTableId"],
                     DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-cd-sg-"),
        Description="sim2real codedeploy agent host: egress only",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": net_tags}])["GroupId"]
    net["sg_id"] = sg_id
    # No ingress rule is added: SSM Session Manager and the CodeDeploy agent are both outbound,
    # and a new security group already permits all egress.
    return net


def _drop_network(ec2, net, deadline):
    """Delete the network this check created, in dependency order, every step retried against one
    SHARED deadline. A failed step does not stop the steps after it (the VPC -- the last one -- is
    the one that matters); the failures raise together once every step has run."""
    steps = []
    if net.get("sg_id"):
        steps.append(lambda: _delete_net(ec2, "delete_security_group", GroupId=net["sg_id"]))
    if net.get("subnet_id"):
        steps.append(lambda: _delete_net(ec2, "delete_subnet", SubnetId=net["subnet_id"]))
    if net.get("igw_id"):
        steps.append(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=net["igw_id"],
                                                         VpcId=net["vpc_id"]))
        steps.append(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=net["igw_id"]))
    steps.append(lambda: _delete_net(ec2, "delete_vpc", VpcId=net["vpc_id"]))
    failures = []
    for step in steps:
        try:
            _try_until(step, deadline)
        except Exception as exc:  # noqa: BLE001 - collected and raised below
            failures.append(exc)
    if failures:
        raise RuntimeError(f"network {net['vpc_id']} was not deleted: {failures!r}") from failures[-1]


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


def _launch_agent_instance(ctx, ec2, net, profile_name, tag_key, tag_value):
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
    deadline = time.monotonic() + 102
    while True:
        try:
            resp = ec2.run_instances(
                ImageId=ami,
                InstanceType=INSTANCE_TYPE,
                MinCount=1,
                MaxCount=1,
                SubnetId=net["subnet_id"],
                SecurityGroupIds=[net["sg_id"]],
                IamInstanceProfile={"Name": profile_name},
                UserData=user_data,
                # Tagged at creation, never after: the deployment group selects the host by
                # exactly this tag.
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
                time.sleep(5)
                continue
            raise
    instance_id = resp["Instances"][0]["InstanceId"]
    _register_host_and_network_teardown(ctx, ec2, instance_id, net)
    return instance_id


def _register_host_and_network_teardown(ctx, ec2, instance_id, net):
    """Terminate the host and delete its network, as ONE cleanup registered LAST so that LIFO runs
    it FIRST. The ordering is load-bearing, not cosmetic.

    The cleanup chain runs under one shared time budget, so ordering decides WHICH resources are
    left behind if it runs out; the network is deleted first because its deletes take longest.

    The terminate lives in here rather than in its own callable for the same reason: the subnet
    cannot be deleted until the instance releases its ENI, so a separate earlier callable would
    spend the entire budget waiting and leave nothing for the deletes it was waiting FOR."""
    def _teardown():
        # 300s: a t3.micro releases its ENI 60-90s after terminate_instances, so the subnet
        # delete needs well over a minute of retries.
        deadline = time.monotonic() + 300.0
        ec2.terminate_instances(InstanceIds=[instance_id])
        # No separate wait for the ENI to be released: delete_subnet retrying on
        # DependencyViolation IS that wait, and folding the two spends the budget ON the delete
        # rather than ahead of it.
        _drop_network(ec2, net, deadline)

    ctx.on_cleanup(_teardown)


def _al2023_ami(ctx):
    """The current AL2023 x86_64 AMI from the public SSM parameter, never a hardcoded id."""
    ssm = ctx.client("ssm")
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), (
        f"the public AL2023 AMI parameter {param!r} returned {value!r}, which is not an AMI id"
    )
    return value


def _wait_ssm_online(ctx, ssm, instance_id, timeout_s=420):
    """Poll DescribeInstanceInformation until SSM reports the instance. An observable
    condition, not a sleep -- and a FAIL if it never arrives."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        infos = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        last = infos[0] if infos else None
        if last and last.get("PingStatus") == "Online":
            return
        time.sleep(5)
    raise AssertionError(
        f"instance {instance_id!r} never came online in SSM within {timeout_s}s; the last "
        f"instance information was {last!r}. The host is provisioned but unreachable, so the "
        f"deployment's effect could not be read even if it succeeded"
    )


def _wait_agent_active(ctx, ssm, instance_id, timeout_s=480):
    """Poll the host until the CodeDeploy agent unit is active.

    SSM reports the instance Online well BEFORE user-data has finished, so a single
    `systemctl is-active` right after DescribeInstanceInformation returns 'inactive' -- the
    agent is still being installed. A host whose agent never becomes active fails with the
    cloud-init tail."""
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        inv = _invoke_command(ctx, ssm, instance_id,
                             ["systemctl is-active codedeploy-agent"], timeout_s=120)
        last = (inv.get("StandardOutputContent") or "").strip()
        if last == "active":
            return last
        time.sleep(2)
    tail = _invoke_command(
        ctx, ssm, instance_id,
        ["tail -n 40 /var/log/cloud-init-output.log 2>&1 || true"], timeout_s=120)
    raise AssertionError(
        f"the CodeDeploy agent on {instance_id!r} never became active within {timeout_s}s; "
        f"'systemctl is-active codedeploy-agent' last returned {last!r}. A host that boots but "
        f"whose agent never registers is provisioned-but-unconnectable, which is a failure and "
        f"not an environment limit. cloud-init tail: "
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
    """Run a shell command and return the raw invocation, whatever its exit status. Retries
    only the documented InvalidInstanceId window while SSM finishes registering the host."""
    deadline = time.monotonic() + 60
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
        f"the deployment {dep_id!r} targets {target_ids!r}, which does not include the tagged "
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


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes and fits the suite's 900s cleanup budget.
_NET_TEARDOWN_S = 630.0
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
        _time.sleep(2)
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
        _time.sleep(2)


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
