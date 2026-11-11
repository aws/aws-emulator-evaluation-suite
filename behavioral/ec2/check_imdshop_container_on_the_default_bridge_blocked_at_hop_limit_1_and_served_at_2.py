"""imdshop-container-on-the-default-bridge-blocked-at-hop-limit-1-and-served-at-2."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "imdshop-container-on-the-default-bridge-blocked-at-hop-limit-1-and-served-at-2"
GROUP = "launch-and-status-async-imdshop"
SERVICES = ["ec2"]

#: t3.small rather than micro: the guest installs and runs a container engine, and 1 GiB makes the
#: package install the slowest step of the check for no gain in what is graded.
_ITYPE = "t3.small"
_AL2023 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded")
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed", "Cancelling")
#: Pulled from ECR Public, not Docker Hub, so an anonymous pull is not rate-limited.
_IMAGE = "public.ecr.aws/docker/library/python:3.12-alpine"
_MARK = "SIM2REAL-IMDSHOP"

# ===== helpers (self-contained) =====


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


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Bounded poll that RAISES on timeout -- never returns its last observation."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _retry_delete(fn, retries=90, delay=10.0):
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
                    Description="sim2real-behav IMDS hop-limit guest role",
                    Tags=[{"Key": "sim2real", "Value": run_tag}])
    ctx.on_cleanup(lambda: _drop_role(iam, role))
    iam.attach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(InstanceProfileName=role,
                                Tags=[{"Key": "sim2real", "Value": run_tag}])
    ctx.on_cleanup(lambda: _drop_instance_profile(iam, role, role))
    iam.add_role_to_instance_profile(InstanceProfileName=role, RoleName=role)
    return role


def _drop_instance_profile(iam, profile_name, role_name):
    for attempt in range(12):
        try:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name,
                                                  RoleName=role_name)
            break
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                break
            if attempt == 11:
                raise
            time.sleep(5)
    for attempt in range(12):
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            return
        except ClientError as exc:
            if _code(exc) == "NoSuchEntity":
                return
            if attempt == 11:
                raise
            time.sleep(5)


def _drop_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if _code(exc) != "NoSuchEntity":
            raise
    # DeleteConflict while the role is still being removed from its instance profile.
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
    """Issue every terminate FIRST, then wait once for all of them to reach 'terminated'.

    Every id here came back from a successful RunInstances, so a NotFound on the terminate is the
    eventual-consistency window, not absence: retried (bounded), never swallowed -- swallowing it
    is how a just-launched instance survives its own teardown. Raises on timeout.
    """
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
                time.sleep(5)
                continue
            raise
    states = {}
    while time.monotonic() < deadline:
        states = _states(ec2, ids)
        if all(s == "terminated" for s in states.values()):
            return
        time.sleep(10)
    raise AssertionError(f"instances not terminated within {timeout_s}s: {states!r}")


def _run_guest(ssm, instance_id, script, what, *, ready_timeout_s=900, run_timeout_s=900):
    """Run a shell script inside the guest via Run Command and return its stdout.

    The SendCommand retry IS the wait for the agent: a host that has just booted rejects
    SendCommand with InvalidInstanceId until its agent has registered, so retrying that call polls
    an observable condition. A host that never accepts a command is a FAIL.
    """
    deadline = time.monotonic() + ready_timeout_s
    while True:
        try:
            sent = ssm.send_command(
                InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                Parameters={"commands": script}, TimeoutSeconds=600,
                Comment="sim2real-behav IMDS hop-limit probe",
            )
            break
        except ClientError as exc:
            if _code(exc) in ("InvalidInstanceId",) + _THROTTLE and time.monotonic() < deadline:
                time.sleep(5)
                continue
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
                timeout_s=run_timeout_s, interval_s=5.0,
                what=f"{what}: invocation {command_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"{what}: the guest script was {inv['Status']!r} ({inv.get('StatusDetails')!r}); "
        f"rc={inv.get('ResponseCode')!r} stdout={inv.get('StandardOutputContent')!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return inv["StandardOutputContent"]


def _set_hop_limit(ec2, iid, hops):
    """Write HttpPutResponseHopLimit and wait for the instance to report it APPLIED -- the wait
    demands the new value as well as 'applied', so a stale block cannot satisfy it."""
    written = ec2.modify_instance_metadata_options(
        InstanceId=iid, HttpPutResponseHopLimit=hops)["InstanceMetadataOptions"]
    assert written["HttpPutResponseHopLimit"] == hops, (
        f"ModifyInstanceMetadataOptions must echo HttpPutResponseHopLimit={hops}, got {written!r}"
    )
    return _poll(lambda: (_instance(ec2, iid) or {}).get("MetadataOptions", {}),
                 lambda o: o.get("State") == "applied" and o.get("HttpPutResponseHopLimit") == hops,
                 timeout_s=300, interval_s=5.0,
                 what=f"{iid} reporting MetadataOptions applied with HttpPutResponseHopLimit={hops}")


# ===== end helpers =====

#: Runs on the host AND inside a container. A transport failure is an OBSERVATION, not an
#: exception: whether the token PUT is answered at all is the whole subject. The PUT, the tokened
#: GET and an untokened (IMDSv1) GET are reported separately, because they behave differently: the
#: hop limit applies to the PUT RESPONSE, so the untokened GET -- refused 401 under
#: HttpTokens=required -- is the twin control proving the container does reach IMDS.
_PROBE = '''\
import json, socket, sys, time, urllib.error, urllib.request

BASE = "http://169.254.169.254"


def call(method, path, headers):
    t0 = time.monotonic()
    req = urllib.request.Request(BASE + path, method=method, headers=headers)
    out = {"status": None, "body": "", "error": None}
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            out.update(status=resp.status, body=resp.read().decode().strip())
    except urllib.error.HTTPError as exc:
        out.update(status=exc.code, error="http")
    except urllib.error.URLError as exc:
        reason = exc.reason
        timed_out = isinstance(reason, (socket.timeout, TimeoutError))
        out["error"] = "timeout" if timed_out else type(reason).__name__ + ":" + str(reason)
    except (socket.timeout, TimeoutError):
        out["error"] = "timeout"
    except OSError as exc:
        out["error"] = type(exc).__name__ + ":" + str(exc)
    out["seconds"] = round(time.monotonic() - t0, 2)
    return out


put = call("PUT", "/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "60"})
rec = {"where": sys.argv[1], "put_status": put["status"], "put_error": put["error"],
       "put_seconds": put["seconds"], "token_len": len(put["body"]),
       "get_status": None, "iid": None}
if put["status"] == 200 and put["body"]:
    got = call("GET", "/latest/meta-data/instance-id", {"X-aws-ec2-metadata-token": put["body"]})
    rec.update(get_status=got["status"], iid=got["body"] or None)
v1 = call("GET", "/latest/meta-data/instance-id", {})
rec.update(v1_status=v1["status"], v1_error=v1["error"])
print("__MARK__ " + json.dumps(rec, sort_keys=True))
'''.replace("__MARK__", _MARK)


def _user_data():
    """Install the container engine and pre-pull the image AT BOOT, then leave a ready/failed
    marker the probe script waits on. Nothing assumes the engine is preinstalled."""
    return (
        "#!/bin/bash\n"
        "set -x\n"
        "mkdir -p /var/lib/sim2real /opt/sim2real\n"
        "cat > /opt/sim2real/probe.py <<'SIM2REAL_PROBE'\n"
        f"{_PROBE}"
        "SIM2REAL_PROBE\n"
        "ok=0\n"
        "if dnf install -y docker && systemctl start docker"
        " && docker info > /var/lib/sim2real/engine-info 2>&1; then\n"
        "  for i in 1 2 3 4 5; do\n"
        f"    if docker pull {_IMAGE}; then ok=1; break; fi\n"
        "    sleep 10\n"
        "  done\n"
        "fi\n"
        "if [ $ok = 1 ]; then touch /var/lib/sim2real/engine-ready;"
        " else touch /var/lib/sim2real/engine-failed; fi\n"
    )


#: Sent via Run Command. Waits (bounded, in the guest) on the marker user data leaves, and if the
#: engine never came up prints exactly what it observed and exits non-zero -- the check then FAILS
#: quoting it. Never a skip.
_PROBE_BOTH = [
    "set -u",
    "for i in $(seq 1 120); do",
    "  if [ -f /var/lib/sim2real/engine-ready ] || [ -f /var/lib/sim2real/engine-failed ]; then"
    " break; fi",
    "  sleep 5",
    "done",
    "if [ ! -f /var/lib/sim2real/engine-ready ]; then",
    "  echo SIM2REAL-ENGINE-NOT-READY markers=$(ls /var/lib/sim2real | tr '\\n' ,)",
    "  systemctl status docker --no-pager 2>&1 | tail -n 20",
    "  tail -n 40 /var/log/cloud-init-output.log",
    "  exit 3",
    "fi",
    "python3 /opt/sim2real/probe.py host",
    f"docker run --rm --network bridge -v /opt/sim2real:/p:ro {_IMAGE} python3 /p/probe.py"
    " container",
    "echo SIM2REAL-CONTAINER-RC=$?",
]


def _probe(ssm, iid, what):
    """{'host': rec, 'container': rec} from one in-guest run, with the container's exit code."""
    out = _run_guest(ssm, iid, _PROBE_BOTH, what)
    recs = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(_MARK + " "):
            rec = json.loads(line[len(_MARK) + 1:])
            assert rec["where"] not in recs, f"{what}: two {rec['where']!r} reports in {out!r}"
            recs[rec["where"]] = rec
    rc = [ln.strip().partition("=")[2] for ln in out.splitlines()
          if ln.strip().startswith("SIM2REAL-CONTAINER-RC=")]
    assert rc == ["0"], (
        f"{what}: the container itself must run and exit 0 (its probe never raises), got rc "
        f"{rc!r}; guest stdout was {out!r}"
    )
    assert set(recs) == {"host", "container"}, (
        f"{what}: expected one host and one container report, got {sorted(recs)!r} from {out!r}"
    )
    return recs


def _assert_served(rec, iid, what):
    assert rec["put_status"] == 200 and rec["token_len"] > 0, (
        f"{what}: the IMDSv2 token PUT must be answered 200 with a token, got {rec!r}"
    )
    assert rec["get_status"] == 200 and rec["iid"] == iid, (
        f"{what}: the tokened GET must serve this instance's own id {iid!r}, got {rec!r}"
    )
    assert rec["v1_status"] == 401, (
        f"{what}: under HttpTokens=required an untokened GET must be refused 401, got {rec!r}"
    )


@tags(
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "axis:rejection",
)
def run(ctx) -> None:
    """At hop limit 1 a container on the default bridge times out on the IMDSv2 token PUT while the
    host is served; at hop limit 2, at launch or after an in-place change, both are served.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    run_tag = "sim2real-imdshop-" + uuid.uuid4().hex[:12]

    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": run_tag}]}]

    az = _usable_az(ec2, _ITYPE)
    ami = ssm.get_parameter(Name=_AL2023)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023} did not resolve to an AMI: {ami!r}"

    launched: list[str] = []
    try:
        subnet = _public_subnet(ctx, ec2, az, tagspec)
        profile = _instance_profile(ctx, iam, "sim2real-imdshop-", run_tag)
        ctx.on_cleanup(lambda: _terminate_and_wait(ec2, launched))

        def _launch(hops):
            inst = _call_with_retry(
                lambda: ec2.run_instances(
                    ImageId=ami, InstanceType=_ITYPE, MinCount=1, MaxCount=1, SubnetId=subnet,
                    IamInstanceProfile={"Name": profile}, UserData=_user_data(),
                    MetadataOptions={"HttpEndpoint": "enabled", "HttpTokens": "required",
                                     "HttpPutResponseHopLimit": hops},
                    TagSpecifications=tagspec("instance") + tagspec("volume"),
                ),
                codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
            )["Instances"][0]
            launched.append(inst["InstanceId"])
            return inst["InstanceId"]

        one, two = _launch(1), _launch(2)
        _poll(lambda: _states(ec2, [one, two]), lambda s: all(v == "running" for v in s.values()),
              timeout_s=600, interval_s=10.0, what=f"{[one, two]!r} reaching 'running'")
        for iid, hops in ((one, 1), (two, 2)):
            opts = _poll(lambda iid=iid: (_instance(ec2, iid) or {}).get("MetadataOptions", {}),
                         lambda o: o.get("State") == "applied", timeout_s=300, interval_s=5.0,
                         what=f"{iid} reporting its launch MetadataOptions applied")
            assert opts.get("HttpPutResponseHopLimit") == hops and \
                opts.get("HttpTokens") == "required", (
                    f"{iid} was launched with hop limit {hops} and HttpTokens=required; "
                    f"DescribeInstances reports {opts!r}"
                )

        # --- hop limit 1: the host is served, the bridged container is not -----------
        # The untokened GET answered 401 is the control proving the container reaches IMDS.
        at1 = _probe(ssm, one, f"hop limit 1 on {one}")
        _assert_served(at1["host"], one, f"host at hop limit 1 ({one})")
        c1 = at1["container"]
        assert c1["put_status"] is None and c1["put_error"] == "timeout", (
            f"at hop limit 1 a container on the default bridge must time out waiting for the "
            f"token PUT response (the extra hop consumes it), got {c1!r}"
        )
        assert c1["token_len"] == 0 and c1["iid"] is None, (
            f"at hop limit 1 the bridged container must obtain no token and no metadata, got "
            f"{c1!r}"
        )
        assert c1["v1_status"] == 401, (
            f"twin control: the same container must still REACH IMDS -- its untokened GET must "
            f"be refused 401 -- or the timeout above is about the network, not the hop limit; got "
            f"{c1!r}"
        )

        # --- hop limit 2 at launch: both are served ----------------------------------
        at2 = _probe(ssm, two, f"hop limit 2 on {two}")
        _assert_served(at2["host"], two, f"host at hop limit 2 ({two})")
        _assert_served(at2["container"], two, f"bridged container at hop limit 2 ({two})")

        # --- repair the hop-1 machine in place: the same container is now served -----
        _set_hop_limit(ec2, one, 2)
        repaired = _probe(ssm, one, f"{one} after its hop limit moved 1 -> 2")
        _assert_served(repaired["host"], one, f"host on {one} after the repair")
        _assert_served(repaired["container"], one,
                       f"bridged container on {one} after the repair (it timed out at 1)")
    finally:
        # The runner bounds its own teardown at 60s, which cannot terminate two instances and
        # release the VPC they held; the LIFO chain runs here, inside the check's own budget.
        ctx.run_cleanups()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
