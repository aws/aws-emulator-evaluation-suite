"""ltver-launch-template-aliases-resolve-to-the-version-each-guest-executes."""
from __future__ import annotations

import base64
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ltver-launch-template-aliases-resolve-to-the-version-each-guest-executes"
GROUP = "launch-and-status-async-ltver"
SERVICES = ["ec2"]

_ITYPE = "t3.micro"
_AL2023 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
_MARK = "SIM2REAL-LTVER"


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=5.0, what="", ctx=None):
    """Bounded poll that RAISES on timeout -- never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _retry_delete(fn, retries=450, delay=2.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind."""
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") \
                    and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
                              "InvalidRouteTableID.NotFound", "InvalidInternetGatewayID.NotFound",
                              "InvalidAssociationID.NotFound", "Gateway.NotAttached",
                              "InvalidLaunchTemplateId.NotFound"):
                return None
            raise


def _usable_az(ec2, itype):
    """An AZ that is BOTH offered for itype and reported available -- both halves load-bearing."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [itype]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no AVAILABLE availability zone offers {itype!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _public_subnet(ctx, ec2, az, tagspec):
    """A VPC of this check's own making with one public subnet: the SSM agent needs egress to its
    endpoint, and nothing here may depend on an ambient default VPC."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    igw = ec2.create_internet_gateway(
        TagSpecifications=tagspec("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    ec2.modify_subnet_attribute(SubnetId=subnet, MapPublicIpOnLaunch={"Value": True})
    rtb = ec2.create_route_table(
        VpcId=vpc, TagSpecifications=tagspec("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rtb)))
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    assoc = ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet)["AssociationId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.disassociate_route_table(AssociationId=assoc)))
    return subnet


def _instance_profile(ctx, iam, prefix, run_tag):
    """A role the SSM agent can register under, plus its instance profile."""
    role = ctx.unique_name(prefix)[:64]
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust,
                    Description="sim2real-behav launch-template alias guest role",
                    Tags=[{"Key": "sim2real", "Value": run_tag}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": run_tag}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    return role


def _drop_instance_profile(iam, profile_name, role_name):
    deadline = time.monotonic() + 60
    while True:
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name,
                                                  RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if _code(exc) not in ("LimitExceeded", "ConcurrentModification") \
                    or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    deadline = time.monotonic() + 60
    while True:
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if _code(exc) != "DeleteConflict" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
    deadline = time.monotonic() + 60
    while True:
        try:
            iam.delete_role(RoleName=role_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if _code(exc) != "DeleteConflict" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _instance(ec2, iid):
    """The instance, or None while a just-minted id is not yet visible (InvalidInstanceID.NotFound
    is EC2's documented eventual-consistency window right after RunInstances)."""
    try:
        pages = list(ec2.get_paginator("describe_instances").paginate(InstanceIds=[iid]))
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    for page in pages:
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == iid:
                    return inst
    return None


def _states(ec2, ids):
    """State per id; an id not yet visible reads as 'unknown', never as 'terminated'."""
    out = {i: "unknown" for i in ids}
    try:
        for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=list(ids)):
            for resv in page["Reservations"]:
                for inst in resv["Instances"]:
                    out[inst["InstanceId"]] = inst["State"]["Name"]
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    return out


def _terminate_and_wait(ec2, ids, timeout_s=900):
    """Terminate every id, then wait for all to reach 'terminated'; raises on timeout.

    Each id came from a successful RunInstances, so NotFound is eventual consistency: retried."""
    ids = sorted(set(ids))
    if not ids:
        return
    deadline = time.monotonic() + timeout_s
    nf_deadline = time.monotonic() + 180
    while True:
        try:
            ec2.terminate_instances(InstanceIds=ids)
            break
        except ClientError as exc:
            if _code(exc) in _THROTTLE or (_code(exc) == "InvalidInstanceID.NotFound"
                                           and time.monotonic() < nf_deadline):
                time.sleep(2)
                continue
            raise
    states = {}
    while time.monotonic() < deadline:
        states = _states(ec2, ids)
        if all(s == "terminated" for s in states.values()):
            return
        time.sleep(2)
    raise AssertionError(f"instances not terminated within {timeout_s}s: {states!r}")


def _run_guest(ctx, ssm, instance_id, script, what, *, ready_timeout_s=900, run_timeout_s=420):
    """Run a shell script inside the guest via Run Command and return its stdout.

    SendCommand returns InvalidInstanceId until the agent registers, so retrying it is the wait."""
    deadline = time.monotonic() + _budget_s(ctx, ready_timeout_s)
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                Parameters={"commands": script}, TimeoutSeconds=600,
                Comment="sim2real-behav launch-template alias guest read",
            )
            break
        except ClientError as exc:
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended before Run Command reached "
                                   f"{instance_id}; not graded") from exc
            raise
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if _code(exc) == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(_invocation, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=_budget_s(ctx, run_timeout_s), interval_s=2.0, ctx=ctx,
                what=f"{what}: invocation {command_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"{what}: the guest script was {inv['Status']!r} ({inv.get('StatusDetails')!r}); "
        f"rc={inv.get('ResponseCode')!r} stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv["StandardOutputContent"]


def _report(stdout, marker):
    """{key: value} from the single `marker k=v ...` line, or None if the guest printed none."""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip().startswith(marker + " ")]
    if len(lines) != 1:
        return None
    return dict(f.partition("=")[::2] for f in lines[0][len(marker):].split() if "=" in f)


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _user_data(label, nonce):
    """User data whose comment line (served by IMDS) and written file (exists only if the script
    ran) both carry the nonce, so "carries" and "executed" are independent observations."""
    return (
        "#!/bin/bash\n"
        f"# {_MARK} label={label} nonce={nonce}\n"
        "mkdir -p /var/lib/sim2real\n"
        f"echo '{nonce}' > /var/lib/sim2real/ltver-ran\n"
    )


#: Read inside the guest: what IMDSv2 serves as this instance's user-data, and what the executed
#: script wrote. The SSM agent can accept commands before cloud-init has run the user data, so the
#: read first waits (bounded) for cloud-init to finish and for the script's file to appear.
_GUEST_READ = [
    "set -u",
    "timeout 240 cloud-init status --wait >/dev/null 2>&1 || true",
    "for i in $(seq 1 45); do [ -f /var/lib/sim2real/ltver-ran ] && break; sleep 1; done",
    "python3 - <<'SIM2REAL_PY'",
    "import re, urllib.request",
    "base = 'http://169.254.169.254'",
    "tok = urllib.request.urlopen(urllib.request.Request(base + '/latest/api/token', method='PUT',"
    " headers={'X-aws-ec2-metadata-token-ttl-seconds': '120'}), timeout=5).read().decode()",
    "def get(p):",
    "    return urllib.request.urlopen(urllib.request.Request(base + p,"
    " headers={'X-aws-ec2-metadata-token': tok}), timeout=5).read().decode()",
    "iid = get('/latest/meta-data/instance-id').strip()",
    "ud = get('/latest/user-data')",
    "m = re.search(r'label=(\\S+) nonce=(\\S+)', ud)",
    "try:",
    "    ran = open('/var/lib/sim2real/ltver-ran').read().strip()",
    "except OSError as exc:",
    "    ran = '__absent_' + type(exc).__name__",
    f"print('{_MARK} iid=%s ud_label=%s ud_nonce=%s ran=%s' % (iid,"
    " m.group(1) if m else '__none', m.group(2) if m else '__none', ran))",
    "SIM2REAL_PY",
]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """$Latest/$Default resolve at launch to the version each guest executes, read in-guest;
    RunInstances UserData overrides the template's; moving the default leaves running instances
    on their launch-time version, and the aws:ec2launchtemplate:version tag agrees.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-launch-template-versions.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    run_tag = "sim2real-ltver-" + uuid.uuid4().hex[:12]
    nonce = {k: f"{k}-{uuid.uuid4().hex}" for k in ("v1", "v2", "override")}

    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": run_tag}]}]

    # --- everything decidable, before anything is created ---------------------
    az = _usable_az(ec2, _ITYPE)
    ami = ssm.get_parameter(Name=_AL2023)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023} did not resolve to an AMI: {ami!r}"

    launched: list[str] = []
    try:
        subnet = _public_subnet(ctx, ec2, az, tagspec)
        profile = _instance_profile(ctx, iam, "sim2real-ltver-", run_tag)

        lt = ec2.create_launch_template(
            LaunchTemplateName=ctx.unique_name("sim2real-ltver-"),
            VersionDescription="sim2real v1",
            LaunchTemplateData={
                "ImageId": ami, "InstanceType": _ITYPE,
                "IamInstanceProfile": {"Name": profile},
                "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
                "UserData": _b64(_user_data("v1", nonce["v1"])),
            },
            TagSpecifications=tagspec("launch-template"),
        )["LaunchTemplate"]
        lt_id = lt["LaunchTemplateId"]
        ctx.on_cleanup(lambda: _retry_delete(
            lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id)))
        v2 = ec2.create_launch_template_version(
            LaunchTemplateId=lt_id, SourceVersion="1", VersionDescription="sim2real v2",
            LaunchTemplateData={"UserData": _b64(_user_data("v2", nonce["v2"]))},
        )["LaunchTemplateVersion"]
        assert v2["VersionNumber"] == 2, f"the second version was numbered {v2['VersionNumber']!r}"
        assert v2["LaunchTemplateData"].get("ImageId") == ami, (
            f"version 2 was created FROM version 1 and must inherit its ImageId {ami!r}; it holds "
            f"{v2['LaunchTemplateData']!r}"
        )
        desc = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
        assert (desc["DefaultVersionNumber"], desc["LatestVersionNumber"]) == (1, 2), (
            f"creating version 2 must move Latest to 2 and leave Default at 1, got {desc!r}"
        )

        # One net for every instance, registered before the first launch; ids are appended the
        # moment RunInstances returns them.
        ctx.on_cleanup(lambda: _terminate_and_wait(ec2, launched))

        def _launch(version, **extra):
            # A brand-new instance profile is not immediately resolvable by RunInstances; that
            # window surfaces as InvalidParameterValue and is the only thing retried.
            inst = _call_with_retry(
                lambda: ec2.run_instances(
                    MinCount=1, MaxCount=1, SubnetId=subnet,
                    LaunchTemplate={"LaunchTemplateId": lt_id, "Version": version},
                    TagSpecifications=tagspec("instance") + tagspec("volume"),
                    **extra,
                ),
                codes=_THROTTLE + ("InvalidParameterValue",), retries=75, delay=2.0,
            )["Instances"][0]
            launched.append(inst["InstanceId"])
            return inst["InstanceId"]

        # --- three launches against Default=1 / Latest=2 --------------------------
        iid = {
            "latest": _launch("$Latest"),
            "default_v1": _launch("$Default"),
            "override": _launch("$Default", UserData=_user_data("override", nonce["override"])),
        }
        first = sorted(iid.values())
        _poll(lambda: _states(ec2, first), lambda s: all(v == "running" for v in s.values()),
              timeout_s=_budget_s(ctx, 600), interval_s=2.0, ctx=ctx,
              what=f"{first!r} all reaching 'running'")

        expect = {"latest": ("v2", "2"), "default_v1": ("v1", "1"), "override": ("override", "1")}
        guest = {}
        for key, (label, version) in expect.items():
            guest[key] = _assert_guest(ctx, ec2, ssm, iid[key], lt_id, label, nonce[label],
                                       version, what=key)

        # --- move the default; the alias now resolves to version 2 ----------------
        mod = ec2.modify_launch_template(LaunchTemplateId=lt_id, DefaultVersion="2")
        assert mod["LaunchTemplate"]["DefaultVersionNumber"] == 2, (
            f"ModifyLaunchTemplate(DefaultVersion='2') must report DefaultVersionNumber 2, got "
            f"{mod['LaunchTemplate']!r}"
        )
        desc = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
        assert (desc["DefaultVersionNumber"], desc["LatestVersionNumber"]) == (2, 2), (
            f"after ModifyLaunchTemplate both pointers must read 2, got {desc!r}"
        )
        iid["default_v2"] = _launch("$Default")
        _poll(lambda: _states(ec2, [iid["default_v2"]]),
              lambda s: all(v == "running" for v in s.values()),
              timeout_s=_budget_s(ctx, 600), interval_s=2.0, ctx=ctx,
              what=f"{iid['default_v2']} reaching 'running'")
        guest["default_v2"] = _assert_guest(ctx, ec2, ssm, iid["default_v2"], lt_id, "v2",
                                            nonce["v2"], "2", what="default_v2")

        # --- the earlier $Default instance was bound at ITS launch, not re-resolved ----
        again = _assert_guest(ctx, ec2, ssm, iid["default_v1"], lt_id, "v1", nonce["v1"], "1",
                              what="default_v1 after the default moved")
        assert again == guest["default_v1"], (
            f"moving the template's default must not change what an already-running $Default "
            f"instance carries: before {guest['default_v1']!r}, after {again!r}"
        )
        assert len({g["ran"] for g in guest.values()}) == 3, (
            f"four guests across three distinct user-data payloads must report exactly three "
            f"distinct nonces, got {guest!r}"
        )
    finally:
        # Terminating four instances and then releasing their VPC takes minutes, so teardown runs
        # here, inside the check's own time budget, on the failure path too.
        ctx.run_cleanups()


def _assert_guest(ctx, ec2, ssm, iid, lt_id, label, nonce, version, *, what):
    """Assert one guest's IMDS user-data, its executed script, and EC2's attribution all agree."""
    out = _run_guest(ctx, ssm, iid, _GUEST_READ, f"{what}: reading user data inside {iid}")
    rec = _report(out, _MARK)
    assert rec is not None, f"{what}: the guest {iid} printed no single {_MARK} line: {out!r}"
    assert rec.get("iid") == iid, (
        f"{what}: the guest that answered for {iid} says it is {rec.get('iid')!r}"
    )
    assert rec.get("ud_label") == label and rec.get("ud_nonce") == nonce, (
        f"{what}: IMDS on {iid} serves user data labelled {rec.get('ud_label')!r} with nonce "
        f"{rec.get('ud_nonce')!r}; expected {label!r} / {nonce!r}"
    )
    assert rec.get("ran") == nonce, (
        f"{what}: the script that cloud-init executed on {iid} wrote {rec.get('ran')!r}; the "
        f"{label!r} payload writes {nonce!r} -- the instance did not EXECUTE the expected version"
    )
    inst = _instance(ec2, iid)
    stamped = {t["Key"]: t["Value"] for t in (inst or {}).get("Tags", [])}
    assert stamped.get("aws:ec2launchtemplate:id") == lt_id, (
        f"{what}: {iid} must be attributed to template {lt_id!r}, tags were {stamped!r}"
    )
    assert stamped.get("aws:ec2launchtemplate:version") == version, (
        f"{what}: EC2 attributes {iid} to template version "
        f"{stamped.get('aws:ec2launchtemplate:version')!r}, but the guest executed the "
        f"{label!r} payload, which belongs to version {version!r}"
    )
    return rec


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
