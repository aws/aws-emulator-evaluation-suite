"""minimum-healthy-hosts-bounds-observed-concurrent-unavailability."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "minimum-healthy-hosts-bounds-observed-concurrent-unavailability"
GROUP = "lifecycle"
SERVICES = ["codedeploy"]

TERMINAL = ("Succeeded", "Failed", "Stopped")
INSTANCE_TYPE = "t3.micro"
VPC_CIDR = "10.184.0.0/16"
SUBNET_CIDR = "10.184.1.0/24"
TAG_KEY = "sim2real-codedeploy-target"
DEST = "/opt/sim2real"

FLEET_SIZE = 2
#: The minimum number of hosts that must stay healthy, as a HOST_COUNT. The expected concurrency
#: bound is DERIVED from this and the observed fleet size (FLEET_SIZE - MIN_HEALTHY), never typed
#: out as a number, so the arithmetic in the API reference is what is being asserted.
MIN_HEALTHY = 1
#: How long each host's BeforeInstall hook sleeps. This is what creates an observable window;
#: it is load-bearing for both the concurrency sampling and the two-sided elapsed assertions.
DWELL_S = 45
SAMPLE_INTERVAL_S = 3
#: Per-host overhead outside the hook sleep (bundle download, Install, event bookkeeping).
TIME_SLACK_S = 40.0
#: The statuses deploymentOverview reports for an in-place deployment. `Ready` is excluded: the
#: model documents it as the count of replacement-environment instances ready to receive
#: traffic in a BLUE/GREEN deployment, and this group is IN_PLACE.
OVERVIEW_IN_PLACE = ("Pending", "InProgress", "Succeeded", "Failed", "Skipped")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """minimumHealthyHosts HOST_COUNT keeps at most (hosts - value) InProgress at once, while an
    AllAtOnce control on the same hosts shows them all InProgress; service-clock elapsed is
    two-sided: the serial leg takes at least two hook dwells, the concurrent leg fewer."""
    cd = ctx.client("codedeploy")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")

    marker = "sim2real-" + ctx.unique_name("")[-12:]
    tag_value = ctx.unique_name("cd-target-")

    bucket = _create_revision_bucket(ctx, s3)
    revision = _put_revision(s3, bucket, "revision.zip", _bundle(marker))

    profile = _create_instance_profile(ctx, bucket)
    az, subnet_id = _create_network(ctx, ec2)
    instance_ids = _launch_agent_instances(
        ctx, ec2, subnet_id, profile, TAG_KEY, tag_value, count=FLEET_SIZE
    )
    _wait_fleet_ready(ctx, ssm, instance_ids)

    app = _create_application(ctx, compute_platform="Server")
    serial_cfg = _create_deployment_config(ctx, cd, MIN_HEALTHY)
    filters = [{"Key": TAG_KEY, "Value": tag_value, "Type": "KEY_AND_VALUE"}]
    concurrent_dg = _create_deployment_group(
        ctx, app, deployment_config="CodeDeployDefault.AllAtOnce", ec2TagFilters=filters
    )
    serial_dg = _create_deployment_group(
        ctx, app, deployment_config=serial_cfg, ec2TagFilters=filters
    )

    # The bound is read back off the service, not taken from the local constant, so what is
    # asserted is the arithmetic on the value the service says it stored.
    stored = cd.get_deployment_config(deploymentConfigName=serial_cfg)["deploymentConfigInfo"]
    mhh = stored.get("minimumHealthyHosts") or {}
    assert mhh.get("type") == "HOST_COUNT" and isinstance(mhh.get("value"), int), (
        f"the custom config {serial_cfg!r} reports minimumHealthyHosts {mhh!r}; the concurrency "
        f"bound below is derived from its type and value, so an unreadable config makes the "
        f"whole check vacuous. Full config: {stored!r}"
    )

    # --- CONTROL leg: nothing bounds concurrency, so the sampler must see the whole fleet ---
    conc = _deploy_and_sample(ctx, cd, app, concurrent_dg, revision)
    assert set(conc["targets"]) == set(instance_ids), (
        f"the AllAtOnce deployment {conc['id']!r} resolved targets {sorted(conc['targets'])!r}; "
        f"the tagged fleet is {sorted(instance_ids)!r}. The derived bound depends on the fleet "
        f"size the service actually selected"
    )
    assert conc["status"] == "Succeeded", (
        f"control leg: the AllAtOnce deployment {conc['id']!r} ended {conc['status']!r} with "
        f"errorInformation {conc['error']!r} on fleet {sorted(instance_ids)!r} in {az!r}"
    )
    assert conc["max_in_progress"] == FLEET_SIZE, (
        f"control leg: the most hosts observed InProgress at one instant during the AllAtOnce "
        f"deployment was {conc['max_in_progress']}, expected the whole fleet ({FLEET_SIZE}). "
        f"The per-sample counts were {conc['samples']!r}. Until an UNBOUNDED config is seen to "
        f"put both hosts out of service at once, 'the bounded config never exceeded 1' is "
        f"satisfied by a target that is simply always serial, or one that never reports a host "
        f"as InProgress at all -- so this leg is what gives the subject leg its meaning"
    )
    conc_elapsed = conc["elapsed"]
    assert conc_elapsed < 2 * DWELL_S, (
        f"control leg: the AllAtOnce deployment took {conc_elapsed:.1f}s by the service's own "
        f"createTime/completeTime, which is not less than two hook dwells ({2 * DWELL_S}s). Each "
        f"host's BeforeInstall sleeps {DWELL_S}s, so a genuinely concurrent deployment of "
        f"{FLEET_SIZE} hosts costs about one dwell. This leg taking two means the fleet was "
        f"serialised despite a config that bounds nothing, and the subject leg below would then "
        f"prove nothing"
    )

    # --- SUBJECT leg: the bound the config declares, observed as a real dip ---
    ser = _deploy_and_sample(ctx, cd, app, serial_dg, revision)
    assert set(ser["targets"]) == set(instance_ids), (
        f"the bounded deployment {ser['id']!r} resolved targets {sorted(ser['targets'])!r}, "
        f"expected the tagged fleet {sorted(instance_ids)!r}"
    )
    assert ser["status"] == "Succeeded", (
        f"subject leg: the bounded deployment {ser['id']!r} ended {ser['status']!r} with "
        f"errorInformation {ser['error']!r}. minimumHealthyHosts bounds concurrency; it must "
        f"not prevent the deployment from completing"
    )
    bound = len(ser["targets"]) - mhh["value"]
    assert ser["max_in_progress"] <= bound, (
        f"subject leg: {ser['max_in_progress']} hosts were observed InProgress at the same "
        f"instant under a config that requires {mhh['value']} of {len(ser['targets'])} to stay "
        f"healthy, so at most {bound} may be out of service at once. The per-sample counts were "
        f"{ser['samples']!r}. A deployment config's minimumHealthyHosts bounds how many hosts "
        f"a deployment takes out of service at once"
    )
    assert ser["max_in_progress"] >= 1, (
        f"subject leg: no sample ever observed a host InProgress during the bounded deployment "
        f"(counts {ser['samples']!r}), so the bound above held vacuously. The control leg saw "
        f"{conc['max_in_progress']}, so the sampler works -- this deployment reached a terminal "
        f"state without any host being observably out of service, which is not a rolling "
        f"deployment"
    )
    ser_elapsed = ser["elapsed"]
    assert ser_elapsed >= 2 * DWELL_S - TIME_SLACK_S, (
        f"subject leg: the bounded deployment took {ser_elapsed:.1f}s by the service's own "
        f"createTime/completeTime; deploying {len(ser['targets'])} hosts at most {bound} at a "
        f"time, each sleeping {DWELL_S}s in BeforeInstall, cannot finish in less than "
        f"{2 * DWELL_S - TIME_SLACK_S:.1f}s. The control leg took {conc_elapsed:.1f}s. A target "
        f"that reports one host InProgress at a time as a display convention while running both "
        f"at once satisfies the concurrency assertion and fails this clock"
    )
    assert ser_elapsed > conc_elapsed, (
        f"subject leg: the bounded deployment ({ser_elapsed:.1f}s) did not take longer than the "
        f"unbounded one ({conc_elapsed:.1f}s) over the same fleet and the same revision. The "
        f"config is the only difference between the two legs, so if it costs no time it is not "
        f"being honoured"
    )

    # --- and the revision really installed on every host, so no leg was an empty deployment ---
    for iid in instance_ids:
        installed = _run_command(ctx, ssm, iid, [f"cat {DEST}/payload.txt"])
        assert installed.strip() == marker, (
            f"{DEST}/payload.txt on {iid!r} reads {installed.strip()!r}, expected the marker "
            f"this run generated ({marker!r}); the concurrency measurements above were taken "
            f"against a deployment that did not install anything on this host"
        )


def _create_deployment_config(ctx, cd, min_healthy):
    name = ctx.unique_name("sim2real-behav-cd-cfg-")
    cd.create_deployment_config(
        deploymentConfigName=name,
        computePlatform="Server",
        minimumHealthyHosts={"type": "HOST_COUNT", "value": min_healthy},
    )
    ctx.on_cleanup(lambda: cd.delete_deployment_config(deploymentConfigName=name))
    return name


def _deploy_and_sample(ctx, cd, app, dg, revision):
    """Create a deployment and sample per-target statuses until terminal; elapsed comes from the
    service's createTime/completeTime, so a slow sampler cannot inflate it."""
    dep_id = cd.create_deployment(
        applicationName=app,
        deploymentGroupName=dg,
        revision=revision,
        # Required: both legs deploy the same revision through two deployment groups, and
        # CodeDeploy tracks prior files per group, so the default DISALLOW fails the second leg.
        fileExistsBehavior="OVERWRITE",
    )["deploymentId"]
    _register_deployment_teardown(ctx, cd, dep_id)

    targets = _poll(
        lambda: _try_list_targets(cd, dep_id),
        lambda ids: len(ids) >= FLEET_SIZE,
        timeout_s=300,
        interval_s=SAMPLE_INTERVAL_S,
        what=(
            f"deployment {dep_id!r} to resolve all {FLEET_SIZE} tagged hosts as targets; a "
            f"deployment that resolves fewer has a different fleet size and a different derived "
            f"concurrency bound"
        ),
    )

    samples = []
    max_in_progress = 0
    deadline = time.monotonic() + 900
    info = None
    while True:
        statuses = _target_statuses(cd, dep_id, targets)
        n_in_progress = sum(1 for s in statuses.values() if s == "InProgress")
        samples.append(n_in_progress)
        max_in_progress = max(max_in_progress, n_in_progress)
        info = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"]
        _assert_overview_partitions_fleet(info, statuses, dep_id)
        if info.get("status") in TERMINAL:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"deployment {dep_id!r} never reached a terminal state within 900s while being "
                f"sampled; last status {info.get('status')!r}, last per-target statuses "
                f"{statuses!r}, InProgress counts so far {samples!r}"
            )
        time.sleep(SAMPLE_INTERVAL_S)

    _assert_overview_eventually_matches(cd, dep_id, statuses)

    # createTime, not startTime: on this deployment shape startTime is absent from deploymentInfo
    # even after Succeeded. completeTime is bounded-retried in case it lags the terminal status.
    done_deadline = time.monotonic() + 180
    created, done = info.get("createTime"), info.get("completeTime")
    while done is None and time.monotonic() < done_deadline:
        time.sleep(3)
        info = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"]
        created, done = info.get("createTime"), info.get("completeTime")
    assert created is not None and done is not None, (
        f"deployment {dep_id!r} reached {info.get('status')!r} without both a createTime "
        f"({created!r}) and a completeTime ({done!r}) even after a 180s bounded retry; the "
        f"elapsed assertions read the service's own clock and cannot fall back to this process's. "
        f"Full deploymentInfo: {info!r}; InProgress samples over the poll: {samples!r}"
    )
    return {
        "id": dep_id,
        "status": info.get("status"),
        "error": info.get("errorInformation"),
        "targets": targets,
        "samples": samples,
        "max_in_progress": max_in_progress,
        "elapsed": (done - created).total_seconds(),
    }


def _assert_overview_partitions_fleet(info, statuses, dep_id):
    """deploymentOverview's in-place buckets always partition the hosts. Overview lags
    BatchGetDeploymentTargets (a host reading InProgress can sit in overview's Pending), so bucket
    agreement is checked only after terminal, in `_assert_overview_eventually_matches`."""
    overview = info.get("deploymentOverview")
    if info.get("status") == "Created":
        # Before the deployment starts, the service has resolved no targets to summarise; the
        # loop re-samples, and the terminal-state deadline is what bounds that.
        return
    assert overview is not None, (
        f"deployment {dep_id!r} is {info.get('status')!r} and reports no deploymentOverview; "
        f"the per-status instance counts are how a caller sees a rolling deployment's shape"
    )
    total = sum(int(overview.get(k, 0)) for k in OVERVIEW_IN_PLACE)
    assert total == len(statuses), (
        f"deployment {dep_id!r} reports deploymentOverview {overview!r}, whose "
        f"{list(OVERVIEW_IN_PLACE)!r} counts total {total}, but it has {len(statuses)} targets "
        f"({statuses!r}). Every host must be in exactly one bucket"
    )


def _assert_overview_eventually_matches(cd, dep_id, final_statuses):
    """Once the deployment is terminal, overview's terminal buckets must catch up to the final
    per-target statuses within a bounded window, though they lag sample-to-sample."""
    wanted = {
        terminal: sum(1 for s in final_statuses.values() if s == terminal)
        for terminal in ("Succeeded", "Failed", "Skipped")
    }
    deadline = time.monotonic() + 60
    overview = {}
    while time.monotonic() < deadline:
        overview = cd.get_deployment(deploymentId=dep_id)["deploymentInfo"].get(
            "deploymentOverview"
        ) or {}
        if all(int(overview.get(k, 0)) == v for k, v in wanted.items()):
            return
        time.sleep(3)
    raise AssertionError(
        f"deployment {dep_id!r} is terminal with final per-target statuses {final_statuses!r} "
        f"(terminal counts {wanted!r}), but deploymentOverview {overview!r} never caught up to "
        f"match within 60s of the deployment reaching a terminal state"
    )


def _try_list_targets(cd, dep_id):
    """Target ids, treating DeploymentNotStartedException (hosts still resolving) as none yet. It is
    the only code swallowed, and the caller's poll raises if targets never appear."""
    try:
        return _list_deployment_targets(cd, dep_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "DeploymentNotStartedException":
            return []
        raise


def _target_statuses(cd, dep_id, target_ids):
    """{instance id -> target status} in ONE BatchGetDeploymentTargets call, so all hosts are
    sampled at one instant rather than across n sequential reads."""
    resp = cd.batch_get_deployment_targets(deploymentId=dep_id, targetIds=list(target_ids))
    out = {}
    for target in resp["deploymentTargets"]:
        inst = target["instanceTarget"]
        out[inst["targetId"]] = inst.get("status")
    assert set(out) == set(target_ids), (
        f"BatchGetDeploymentTargets for {dep_id!r} returned statuses for {sorted(out)!r}, "
        f"asked about {sorted(target_ids)!r}; a concurrency count over a partial fleet is wrong"
    )
    return out


def _bundle(payload_marker):
    """A revision whose BeforeInstall hook sleeps, so each host is observably out of service for
    a window wide enough to sample. The sleep is inside the HOOK, on the host -- it is the
    subject being measured, not a wait in this check."""
    appspec = (
        "version: 0.0\n"
        "os: linux\n"
        "files:\n"
        "  - source: payload.txt\n"
        f"    destination: {DEST}\n"
        "hooks:\n"
        "  BeforeInstall:\n"
        "    - location: before_install.sh\n"
        f"      timeout: {DWELL_S * 4}\n"
        "      runas: root\n"
    )
    return {
        "appspec.yml": appspec,
        "payload.txt": payload_marker,
        "before_install.sh": (
            "#!/bin/bash\n"
            "set -uo pipefail\n"
            f"sleep {DWELL_S}\n"
            "exit 0\n"
        ),
    }


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
    """create_deployment, register its teardown, then poll to terminal. Teardown is registered first
    so a hung deployment is still driven terminal: a non-terminal one blocks group deletion."""
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
    # IAM exposes no condition reporting that a freshly attached policy has become effective;
    # the bounded InvalidRoleException retry in _create_deployment_group is what makes this
    # correct, and it is what fails loudly if the grant never lands.
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
    deadline = time.monotonic() + 90
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
    # IAM exposes no condition reporting that an instance profile has become usable by
    # RunInstances; the bounded retry in _launch_agent_instance is what makes this correct.
    return profile_name


def _create_network(ctx, ec2):
    """A VPC with one public subnet, created in-check since an account may have no default VPC.
    Egress is required: the agent installs from the regional CodeDeploy bucket and long-polls it."""
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
    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": rtags}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=SUBNET_CIDR,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": rtags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": rtags}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    )
    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": rtags}]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt_id))
    ec2.create_route(
        RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)[
        "AssociationId"
    ]
    ctx.on_cleanup(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))
    return az, subnet_id


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
    """Launch `count` instances that install the CodeDeploy agent from user-data, in ONE
    RunInstances call so their provisioning overlaps."""
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
    deadline = time.monotonic() + 120
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
                # Tagged at creation, never after, so an instance is never untagged while it
                # bills. The deployment group selects these hosts by exactly this tag.
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
    """Every host reachable through SSM AND running the CodeDeploy agent. A host whose agent never
    registers is a failure, not an environment limit: no deployment could reach it."""
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
    """[(name, status, startTime, endTime, diagnostics)] in service order. A list, not a dict: the
    order is asserted, and a dict would hide a canned unordered event set."""
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
    """True iff `sub` appears in `full` in order (gaps allowed): which documented events occur
    depends on deployment type and hooks, so the test is a subsequence of the documented order."""
    it = iter(full)
    return all(any(x == y for y in it) for x in sub)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
