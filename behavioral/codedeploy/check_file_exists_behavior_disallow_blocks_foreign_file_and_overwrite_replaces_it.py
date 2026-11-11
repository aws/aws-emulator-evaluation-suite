"""file-exists-behavior-disallow-blocks-foreign-file-and-overwrite-replaces-it."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

# CodeDeploy's fileExistsBehavior check is keyed on PATH MEMBERSHIP in the previous successful
# deployment's manifest, not on the bytes there: rewriting an installed file out of band does not
# make it foreign. So each conflicting path appears in a revision for the first time only after its
# out-of-band content is already on disk.

CHECK = "file-exists-behavior-disallow-blocks-foreign-file-and-overwrite-replaces-it"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]

TERMINAL = ("Succeeded", "Failed", "Stopped")
INSTANCE_TYPE = "t3.micro"
VPC_CIDR = "10.185.0.0/16"
SUBNET_CIDR = "10.185.1.0/24"
TAG_KEY = "sim2real-codedeploy-target"
DEST = "/opt/sim2real"
APP_FILE = DEST + "/app.txt"
EXTRA_DISALLOW_FILE = DEST + "/extra_disallow.txt"
EXTRA_OVERWRITE_FILE = DEST + "/extra_overwrite.txt"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """fileExistsBehavior decides what happens when a revision's file already exists on the host:
    DISALLOW fails the Install event and leaves the foreign bytes, removing the file lets the same
    deployment succeed, and OVERWRITE replaces the bytes; all read off the host.

    Reference: https://docs.aws.amazon.com/codedeploy/latest/APIReference/API_CreateDeployment.html
    """
    cd = ctx.client("codedeploy")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")

    app_marker = "sim2real-app-" + ctx.unique_name("")[-12:]
    extra_marker = "sim2real-extra-" + ctx.unique_name("")[-12:]
    overwrite_marker = "sim2real-ovr-" + ctx.unique_name("")[-12:]
    foreign_marker = "sim2real-foreign-" + ctx.unique_name("")[-12:]
    foreign_marker2 = "sim2real-foreign2-" + ctx.unique_name("")[-12:]
    tag_value = ctx.unique_name("cd-target-")

    bucket = _create_revision_bucket(ctx, s3)
    # THREE revisions: a conflict is genuine only the first time a path appears in a revision's
    # manifest while foreign content already sits there (see the module note).
    revision_a = _put_revision(s3, bucket, "revision-a.zip", _bundle({"app.txt": app_marker}))
    revision_b = _put_revision(
        s3,
        bucket,
        "revision-b.zip",
        _bundle({"app.txt": app_marker, "extra_disallow.txt": extra_marker}),
    )
    revision_c = _put_revision(
        s3,
        bucket,
        "revision-c.zip",
        _bundle(
            {
                "app.txt": app_marker,
                "extra_disallow.txt": extra_marker,
                "extra_overwrite.txt": overwrite_marker,
            }
        ),
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

    # --- beat 1: positive control, no conflict, default fileExistsBehavior ---
    # revision A never mentions extra_disallow.txt, so neither later path is "adopted" yet.
    ok_id, ok_info = _deploy_and_wait(ctx, cd, app, dg, revision_a)
    assert ok_info.get("status") == "Succeeded", (
        f"positive control: the deployment {ok_id!r} onto {instance_id!r} in {az!r} with no "
        f"pre-existing conflict ended {ok_info.get('status')!r} with errorInformation "
        f"{ok_info.get('errorInformation')!r}. Until this leg passes, a Failed deployment below "
        f"cannot be attributed to a file conflict"
    )
    seen = _read_many(ctx, ssm, instance_id, [APP_FILE, EXTRA_DISALLOW_FILE])
    assert seen[APP_FILE] == app_marker, (
        f"positive control: {APP_FILE} reads "
        f"{seen[APP_FILE]!r}, expected {app_marker!r}"
    )
    assert seen[EXTRA_DISALLOW_FILE] == "", (
        f"positive control: {EXTRA_DISALLOW_FILE} reads "
        f"{seen[EXTRA_DISALLOW_FILE]!r} before revision A -- which never "
        f"mentions this path -- has deployed at all; the conflict beat 2 manufactures would not "
        f"be genuine if something already sat here"
    )

    # --- beat 2: break exactly one thing -- a FOREIGN file at a path revision A never touched,
    # so it is a genuine, never-adopted conflict.
    _write_foreign(ctx, ssm, instance_id, EXTRA_DISALLOW_FILE, foreign_marker)

    # --- beat 3: the specific refusal, under the DEFAULT (DISALLOW) behaviour ---
    bad_id, bad_info = _deploy_and_wait(ctx, cd, app, dg, revision_b)
    assert bad_info.get("status") == "Failed", (
        f"a deployment whose revision installs {EXTRA_DISALLOW_FILE} for the FIRST time, and "
        f"which already exists at the destination from an out-of-band write, must FAIL under "
        f"the default fileExistsBehavior=DISALLOW; {bad_id!r} ended {bad_info.get('status')!r} "
        f"with errorInformation {bad_info.get('errorInformation')!r}"
    )
    bad_events = _events_in_order(_instance_target(cd, bad_id, instance_id))
    bad_status = {n: s for n, s, _, _, _ in bad_events}
    assert bad_status.get("Install") == "Failed", (
        f"the Install lifecycle event reads {bad_status.get('Install')!r} on a deployment that "
        f"failed on a file conflict, expected 'Failed': Install is the event during which the "
        f"agent copies revision files to their final destination, so it is the event that must "
        f"carry the refusal. Events: {[(n, s) for n, s, _, _, _ in bad_events]!r}"
    )
    install_diag = next(d for n, _, _, _, d in bad_events if n == "Install")
    assert install_diag.get("errorCode") or install_diag.get("message"), (
        f"the failed Install event carries no diagnostics at all ({install_diag!r}); an "
        f"operator has no way to learn WHICH file conflicted. The deployment-level "
        f"errorInformation was {bad_info.get('errorInformation')!r}"
    )

    # --- beat 4: the CONFLICTING file's effect is absent -- it never receives the revision's
    # bytes. This is the part of the contract fileExistsBehavior actually governs.
    seen = _read_many(ctx, ssm, instance_id, [EXTRA_DISALLOW_FILE, APP_FILE])
    assert seen[EXTRA_DISALLOW_FILE] == foreign_marker, (
        f"{EXTRA_DISALLOW_FILE} reads {seen[EXTRA_DISALLOW_FILE]!r} "
        f"after a DISALLOW refusal; it must still hold the foreign bytes {foreign_marker!r} and "
        f"must NOT hold the revision's {extra_marker!r}. DISALLOW means the deployment fails, "
        f"not that it copies and then reports a failure"
    )
    # A DISALLOW refusal is not transactional across the revision: Install clears destination paths
    # before copying and aborts on the first conflict, so app.txt is left missing ('').
    app_after_refusal = seen[APP_FILE]
    assert app_after_refusal == "", (
        f"{APP_FILE} reads {app_after_refusal!r} after a DISALLOW refusal on {EXTRA_DISALLOW_FILE}; "
        f"expected '' -- a failed Install on this agent clears destination paths ahead of "
        f"copying and aborts on the first conflict, so a non-conflicting file from the same "
        f"revision is left missing rather than restored to its previous content "
        f"({app_marker!r})"
    )

    # --- beat 5: restore -- remove the conflict, the IDENTICAL deployment succeeds ---
    _run_command(ctx, ssm, instance_id, [f"rm -f {EXTRA_DISALLOW_FILE}"])
    restore_id, restore_info = _deploy_and_wait(ctx, cd, app, dg, revision_b)
    assert restore_info.get("status") == "Succeeded", (
        f"restore: with the foreign file removed, the IDENTICAL deployment ended "
        f"{restore_info.get('status')!r} on {restore_id!r} (errorInformation="
        f"{restore_info.get('errorInformation')!r}). The request never changed, so the refusal "
        f"above was either not caused by the conflict or the fixture has died"
    )
    seen = _read_many(ctx, ssm, instance_id, [EXTRA_DISALLOW_FILE, APP_FILE])
    assert seen[EXTRA_DISALLOW_FILE] == extra_marker, (
        f"restore: {EXTRA_DISALLOW_FILE} reads "
        f"{seen[EXTRA_DISALLOW_FILE]!r}, expected the revision's "
        f"{extra_marker!r} now that nothing conflicts"
    )
    assert seen[APP_FILE] == app_marker, (
        f"restore: {APP_FILE} reads {seen[APP_FILE]!r}, expected the "
        f"revision's {app_marker!r}: a SUCCEEDED Install must recopy every file in the revision, "
        f"including the one the previous, failed attempt had left missing"
    )

    # --- beat 6: OVERWRITE both accepts the conflict AND replaces the bytes ---
    # extra_overwrite.txt has never been in any revision's manifest (A or B) either, so this is
    # a fresh, never-adopted conflict too -- not a re-test of the path beat 3 already exercised.
    _write_foreign(ctx, ssm, instance_id, EXTRA_OVERWRITE_FILE, foreign_marker2)
    ow_id, ow_info = _deploy_and_wait(
        ctx, cd, app, dg, revision_c, fileExistsBehavior="OVERWRITE"
    )
    assert ow_info.get("status") == "Succeeded", (
        f"the same kind of never-adopted conflict that DISALLOW refuses must be accepted with "
        f"fileExistsBehavior='OVERWRITE'; {ow_id!r} ended {ow_info.get('status')!r} with "
        f"errorInformation {ow_info.get('errorInformation')!r}"
    )
    assert ow_info.get("fileExistsBehavior") == "OVERWRITE", (
        f"GetDeployment reports fileExistsBehavior {ow_info.get('fileExistsBehavior')!r} for "
        f"{ow_id!r}, expected 'OVERWRITE': the value the deployment ran under must be readable "
        f"back, or the outcome below cannot be attributed to it"
    )
    final = _read(ctx, ssm, instance_id, EXTRA_OVERWRITE_FILE)
    assert final == overwrite_marker, (
        f"{EXTRA_OVERWRITE_FILE} reads {final!r} after an OVERWRITE deployment; it must hold "
        f"the REVISION's bytes {overwrite_marker!r} and not the foreign {foreign_marker2!r}. "
        f"This is the assertion that separates a target which accepts the parameter from one "
        f"which honours it: the deployment reported Succeeded either way"
    )
    ow_events = {
        n: s for n, s, _, _, _ in _events_in_order(_instance_target(cd, ow_id, instance_id))
    }
    assert ow_events.get("Install") == "Succeeded", (
        f"the OVERWRITE deployment's Install event reads {ow_events.get('Install')!r}, expected "
        f"'Succeeded' -- the bytes at the destination changed, so the copy happened and the "
        f"record must say so. Events: {ow_events!r}"
    )


def _bundle(files):
    """A revision installing every file in `files` (destination-relative name -> content).
    Each entry is a separate `files:` mapping in the appspec so a caller can grow the manifest
    across revisions -- e.g. revision A installs only app.txt so extra_disallow.txt and
    extra_overwrite.txt stay "never adopted" until the revision that first lists them."""
    file_lines = "".join(
        f"  - source: {name}\n    destination: {DEST}\n" for name in files
    )
    appspec = f"version: 0.0\nos: linux\nfiles:\n{file_lines}"
    return {"appspec.yml": appspec, **files}


def _write_foreign(ctx, ssm, instance_id, path, marker):
    """Put a file CodeDeploy did not install at `path`, and confirm it landed -- the conflict is
    the negative's whole input, so a silent failure to create it would turn the refusal leg into
    a false pass."""
    _run_command(
        ctx,
        ssm,
        instance_id,
        [f"mkdir -p {DEST}", f"printf '%s' '{marker}' > {path}"],
    )
    got = _read(ctx, ssm, instance_id, path)
    assert got == marker, (
        f"the out-of-band write of the conflicting file left {path} reading {got!r}, expected "
        f"{marker!r}; without the conflict in place the DISALLOW leg would pass for the wrong "
        f"reason"
    )


def _read(ctx, ssm, instance_id, path):
    """A file's contents as the host reads them, or '' when absent."""
    return _run_command(ctx, ssm, instance_id, [f"cat {path} 2>/dev/null || true"]).strip()


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _read_many(ctx, ssm, instance_id, paths):
    """Several files' contents in one SSM invocation, each '' when absent."""
    sep = "sim2real-file-boundary"
    commands = []
    for path in paths:
        commands += [f"cat {path} 2>/dev/null || true", f"echo; echo {sep}"]
    parts = _run_command(ctx, ssm, instance_id, commands).split(sep)
    return {path: parts[i].strip() for i, path in enumerate(paths)}


def _poll(ctx, fn, pred, *, timeout_s, interval_s, what):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
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
        ctx,
        lambda: cd.get_deployment(deploymentId=dep_id)["deploymentInfo"],
        lambda i: i.get("status") in TERMINAL,
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=2,
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
            time.sleep(2)
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
    deadline = time.monotonic() + _budget_s(ctx, 90)
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
    return profile_name


def _create_network(ctx, ec2):
    """A VPC with one public subnet, created in-check rather than assuming a default VPC.

    Egress is required: the agent installs itself from the regional CodeDeploy bucket and then
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

    One RunInstances call, so the hosts provision in parallel.
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
    deadline = time.monotonic() + _budget_s(ctx, 120)
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
                # Tagged at creation so an instance is never untagged; the deployment group
                # selects these hosts by exactly this tag.
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
                time.sleep(2)
                continue
            if unpropagated and _budget_spent(ctx):
                raise TimeoutError("RunInstances past the instance profile's propagation: the run budget ended first; not graded") from exc
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
    deadline = time.monotonic() + _budget_s(ctx, online_s)
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
            time.sleep(2)
    if pending and _budget_spent(ctx):
        raise TimeoutError(f"{sorted(pending)!r} Online in SSM: the run budget ended first; not graded")
    assert not pending, (
        f"{sorted(pending)!r} never came online in SSM within {online_s}s (last ping statuses "
        f"{last!r}); the hosts are provisioned but unreachable, so the deployment's effect "
        f"could not be read even if it succeeded"
    )
    deadline = time.monotonic() + _budget_s(ctx, agent_s)
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
    if pending and _budget_spent(ctx):
        raise TimeoutError(f"the CodeDeploy agent active on {sorted(pending)!r}: the run budget ended first; not graded")
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
    deadline = time.monotonic() + _budget_s(ctx, 90)
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
                time.sleep(2)
                continue
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceId" and _budget_spent(ctx):
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

    A list, not a dict, because the order is asserted.
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
