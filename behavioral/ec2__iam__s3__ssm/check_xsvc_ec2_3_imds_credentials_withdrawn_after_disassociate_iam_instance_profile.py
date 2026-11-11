"""xsvc-ec2-3-imds-credentials-withdrawn-after-disassociate-iam-instance-profile."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "xsvc-ec2-3-imds-credentials-withdrawn-after-disassociate-iam-instance-profile"
GROUP = "instance-credentials-lifecycle"
SERVICES = ["ec2", "iam", "s3", "ssm"]

_SCENARIO = "xsvc-ec2-3-imds-disassociate"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_VPC_CIDR = "10.94.0.0/16"
_SUBNET_CIDR = "10.94.1.0/24"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


@tags(
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "axis:happy-path",
)
def run(ctx) -> None:
    """After DisassociateIamInstanceProfile, the guest's IMDSv2 role listing and iam/info answer
    404, its credential chain finds nothing and its S3 write fails; the instance keeps running.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")

    az = _usable_zone(ec2)
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    stem = ctx.unique_name("sim2real-xsvc-imdsdis-")
    bucket = _bucket(ctx, s3, stem)
    role = f"{stem}-role"
    _instance_role(ctx, iam, role, bucket)
    profile = _instance_profile(ctx, iam, role)
    subnet, sg = _network(ctx, ec2, az, stem)
    instance_id = _launch(ctx, ec2, ami, subnet, sg, profile, stem)
    _await_agent(ctx, ssm, instance_id)

    # Positive control: the same probe on the same instance while the association is live.
    m1 = ctx.unique_name("m1-")
    p1 = _run_probe(ctx, ssm, instance_id, _probe_script(ctx.region, bucket, m1))
    assert p1["list_http"] == "200" and p1["listed_role"] == role, (
        f"before disassociation IMDS must list {role!r}; got http={p1['list_http']!r} "
        f"body={p1['listed_role']!r}")
    assert p1["info_http"] == "200" and p1["info_profile_arn"].endswith(
        f"instance-profile/{profile}"), (
        f"iam/info must name profile {profile!r}; got http={p1['info_http']!r} "
        f"arn={p1['info_profile_arn']!r}")
    assert p1["sts_rc"] == 0 and f"assumed-role/{role}/" in p1["sts_out"], (
        f"the guest's credential chain must resolve to the instance role; rc={p1['sts_rc']!r} "
        f"out={p1['sts_out']!r} err={p1['sts_err']!r}")
    assert p1["put_rc"] == 0, f"the write must succeed: rc={p1['put_rc']!r} err={p1['put_err']!r}"
    assert s3.head_object(Bucket=bucket, Key=m1)["ContentLength"] == len(m1), "write missing at S3"

    assocs = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}])["IamInstanceProfileAssociations"]
    live = [a for a in assocs if a["State"] == "associated"]
    assert len(live) == 1, f"exactly one associated profile expected before the change: {assocs!r}"
    # The call's own response reports the transient disassociating state; the terminal outcome
    # (no association left that is not disassociated) is what the poll below grades.
    gone = ec2.disassociate_iam_instance_profile(AssociationId=live[0]["AssociationId"])
    assert gone["IamInstanceProfileAssociation"]["State"] == "disassociating", (
        f"DisassociateIamInstanceProfile must report disassociating; got {gone!r}")
    _poll(ctx, lambda: [a for a in ec2.describe_iam_instance_profile_associations(
              Filters=[{"Name": "instance-id", "Values": [instance_id]}])
              ["IamInstanceProfileAssociations"] if a["State"] != "disassociated"],
          lambda left: left == [], 300, 2, f"{instance_id} having no live association")

    p2 = _poll(ctx, lambda: _run_probe(ctx, ssm, instance_id,
                                       _probe_script(ctx.region, bucket, ctx.unique_name("m2-"))),
               lambda p: p["list_http"] != "200", 600, 2,
               f"IMDS on {instance_id} withdrawing the role after disassociation")
    assert p2["list_http"] == "404", (
        f"with no profile associated the credentials listing must answer 404; got "
        f"{p2['list_http']!r} body={p2['listed_role']!r}")
    assert p2["info_http"] == "404", (
        f"with no profile associated iam/info must answer 404; got {p2['info_http']!r}")
    assert p2["sts_rc"] != 0 and "Unable to locate credentials" in p2["sts_err"], (
        f"the guest's credential chain must find nothing; rc={p2['sts_rc']!r} "
        f"out={p2['sts_out']!r} err={p2['sts_err']!r}")
    assert p2["put_rc"] != 0, f"the write must now fail; err={p2['put_err']!r}"
    code = _head_code(s3, bucket, p2["marker"])
    assert code == "404", f"the failed write must not exist at S3; HeadObject said {code!r}"
    state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert state["State"]["Name"] == "running" and "IamInstanceProfile" not in state, (
        f"the instance must stay running with no profile; got state={state['State']!r} "
        f"profile={state.get('IamInstanceProfile')!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, predicate, timeout_s, interval_s, what):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} not met within {timeout_s:.0f}s (last observed: {last!r})")
        time.sleep(interval_s)


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _tags(kind, name):
    return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name},
                                            {"Key": "sim2real", "Value": _SCENARIO}]}]


def _head_code(s3, bucket, key):
    """The code HeadObject answers with. RAISES if the object exists."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return str(exc.response["Error"]["Code"])
    raise AssertionError(f"s3://{bucket}/{key} was expected not to exist and HeadObject found it")


def _bucket(ctx, s3, name):
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    ctx.on_cleanup(_empty_and_delete)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    return name


def _instance_role(ctx, iam, name, bucket):
    arn = iam.create_role(
        RoleName=name, Description="sim2real-xsvc imds s3 authz",
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY))
    iam.put_role_policy(RoleName=name, PolicyName="one-bucket", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket}/*"}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="one-bucket"))
    return arn


def _instance_profile(ctx, iam, role):
    name = f"{role}-prof"
    iam.create_instance_profile(InstanceProfileName=name,
                                Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=name, RoleName=role))
    return name


def _usable_zone(ec2):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {_INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _retry_dep(fn, budget_s=600):
    deadline = time.time() + budget_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return None
            if code not in ("DependencyViolation", "InvalidNetworkInterface.InUse") \
                    or time.time() > deadline:
                raise RuntimeError(f"teardown gave up: {code}: {exc}") from exc
            time.sleep(2)


def _network(ctx, ec2, az, stem):
    """Own VPC with one public subnet so the SSM agent can register. Nothing ambient is used."""
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=_tags("vpc", stem))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.delete_vpc(VpcId=vpc)))
    try:
        ec2.get_waiter("vpc_available").wait(
            VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 600) // 2))})
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"VPC {vpc} available: the run budget ended first; not graded") from None
        raise
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})
    igw = ec2.create_internet_gateway(
        TagSpecifications=_tags("internet-gateway", stem))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw)))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.detach_internet_gateway(
        InternetGatewayId=igw, VpcId=vpc)))
    rts = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"]
    assert len(rts) == 1, f"a new VPC must have exactly one route table; got {rts!r}"
    ec2.create_route(RouteTableId=rts[0]["RouteTableId"], DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw)
    sn = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
                           TagSpecifications=_tags("subnet", stem))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.delete_subnet(SubnetId=sn)))
    ec2.modify_subnet_attribute(SubnetId=sn, MapPublicIpOnLaunch={"Value": True})
    sgs = [g["GroupId"] for g in ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc]},
                 {"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]]
    assert len(sgs) == 1, f"the new VPC must have exactly one default security group; got {sgs!r}"
    return sn, sgs[0]


def _launch(ctx, ec2, ami, subnet, sg, profile, stem):
    # A brand-new instance profile is not immediately resolvable by RunInstances.
    r = _call_with_retry(lambda: ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet, SecurityGroupIds=[sg], IamInstanceProfile={"Name": profile},
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
        TagSpecifications=_tags("instance", stem) + _tags("volume", stem)),
        codes=_THROTTLE + ("InvalidParameterValue",), retries=75, delay=2.0)
    iid = r["Instances"][0]["InstanceId"]

    def _terminate():
        ec2.terminate_instances(InstanceIds=[iid])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[iid], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(_terminate)
    return iid


def _await_agent(ctx, ssm, iid):
    def _agent():
        for page in ssm.get_paginator("describe_instance_information").paginate(
                Filters=[{"Key": "InstanceIds", "Values": [iid]}]):
            for info in page["InstanceInformationList"]:
                if info.get("InstanceId") == iid:
                    return info
        return None
    _poll(ctx, _agent, lambda i: i is not None and i.get("PingStatus") == "Online", 600, 2,
          f"the SSM agent on {iid} coming Online")


def _probe_script(region, bucket, marker):
    """One JSON line describing what IMDSv2 serves and what the guest's default credential chain
    can do. Uses the CLI's own IMDS resolver (no exported keys), so a withdrawn role is visible as
    the chain finding nothing. Only the caller ARN ever leaves the guest."""
    return [
        "set -uo pipefail",
        "IMDS=http://169.254.169.254",
        'T=$(curl -sS -X PUT "$IMDS/latest/api/token" '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300")',
        'H="X-aws-ec2-metadata-token: $T"',
        'LH=$(curl -sS -o /tmp/list.txt -w "%{http_code}" -H "$H" '
        '"$IMDS/latest/meta-data/iam/security-credentials/")',
        'IH=$(curl -sS -o /tmp/info.json -w "%{http_code}" -H "$H" '
        '"$IMDS/latest/meta-data/iam/info")',
        f"export AWS_DEFAULT_REGION={region}",
        f"echo -n {marker} > /tmp/body",
        "aws sts get-caller-identity --query Arn --output text >/tmp/sts.out 2>/tmp/sts.err; STSRC=$?",
        f"aws s3api put-object --bucket {bucket} --key {marker} --body /tmp/body "
        "> /dev/null 2>/tmp/put.err; PUTRC=$?",
        f"export LH IH STSRC PUTRC M={marker}",
        "python3 - <<'PYSUM'",
        "import json, os",
        "def text(p):",
        "    try:",
        "        return open(p).read()[:300]",
        "    except OSError:",
        '        return ""',
        "def load(p):",
        "    try:",
        "        return json.load(open(p))",
        "    except (OSError, ValueError):",
        "        return {}",
        'ok = os.environ["LH"] == "200"',
        "print(json.dumps({",
        '    "marker": os.environ["M"], "list_http": os.environ["LH"],',
        '    "listed_role": text("/tmp/list.txt").strip().splitlines()[0] if ok else text("/tmp/list.txt")[:80],',
        '    "info_http": os.environ["IH"],',
        '    "info_profile_arn": load("/tmp/info.json").get("InstanceProfileArn", "") if os.environ["IH"] == "200" else "",',
        '    "sts_rc": int(os.environ["STSRC"]), "sts_out": text("/tmp/sts.out").strip(),',
        '    "sts_err": text("/tmp/sts.err"),',
        '    "put_rc": int(os.environ["PUTRC"]), "put_err": text("/tmp/put.err"),',
        "}))",
        "PYSUM",
    ]


def _run_probe(ctx, ssm, iid, script):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[iid], DocumentName="AWS-RunShellScript",
        Parameters={"commands": script}, TimeoutSeconds=180,
        Comment="sim2real-xsvc imds s3 authz probe"))
    cid = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=cid, InstanceId=iid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvocationDoesNotExist":
                return None
            raise
    inv = _poll(ctx, _inv, lambda i: i is not None and i.get("Status") in _TERMINAL, 240, 1,
                f"invocation {cid} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"the probe must run to completion; SSM reports {inv['Status']!r} "
        f"stderr={inv.get('StandardErrorContent')!r}")
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.startswith("{")]
    assert lines, f"the probe printed no JSON; stdout={inv['StandardOutputContent']!r}"
    return json.loads(lines[-1])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
