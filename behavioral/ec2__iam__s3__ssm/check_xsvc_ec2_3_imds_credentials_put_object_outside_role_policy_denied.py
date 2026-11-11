"""xsvc-ec2-3-imds-credentials-put-object-outside-role-policy-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "xsvc-ec2-3-imds-credentials-put-object-outside-role-policy-denied"
GROUP = "instance-credentials-authorization"
SERVICES = ["ec2", "iam", "s3", "ssm"]

_SCENARIO = "xsvc-ec2-3-imds-s3-authz"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_VPC_CIDR = "10.93.0.0/16"
_SUBNET_CIDR = "10.93.1.0/24"
_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


@tags("cap:c7", "axis:rejection", "concern:negative-classes", "concern:data-plane",
      "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """IMDSv2 credentials in the guest may PutObject only where the role allows: the other bucket is
    AccessDenied, and so is the permitted one once its bucket policy explicitly denies the role.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    az = _usable_zone(ec2)
    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    stem = ctx.unique_name("sim2real-xsvc-imdss3-")
    allowed = _bucket(ctx, s3, f"{stem}-ok")
    other = _bucket(ctx, s3, f"{stem}-no")

    role = f"{stem}-role"
    role_arn = _instance_role(ctx, iam, role, allowed)
    profile = _instance_profile(ctx, iam, role)

    subnet, sg = _network(ctx, ec2, az, stem)
    instance_id = _launch(ctx, ec2, ami, subnet, sg, profile, stem)
    _await_agent(ctx, ssm, instance_id)

    # Identity policy only.
    m1 = ctx.unique_name("m1-")
    p1 = _run_probe(ctx, ssm, instance_id, _probe_script(ctx.region, allowed, other, m1))
    assert p1["listed_role"] == role, (
        f"IMDSv2 must list the instance profile's role {role!r}; it listed {p1['listed_role']!r}")
    assert p1["code"] == "Success" and p1["akid_prefix"] == "ASIA", (
        f"IMDS must serve temporary credentials (Code Success, ASIA key); got code="
        f"{p1['code']!r} prefix={p1['akid_prefix']!r}")
    assert p1["caller_arn_role"] == role, (
        f"STS must identify the IMDS credentials as the assumed instance role {role!r}; "
        f"GetCallerIdentity reported {p1['caller_arn_role']!r}")
    assert p1["ok_rc"] == 0, (
        f"the role allows s3:PutObject on {allowed}, so that write must succeed; rc="
        f"{p1['ok_rc']!r} err={p1['ok_err']!r}")
    session = f"arn:aws:sts::{account}:assumed-role/{role}/{instance_id}"
    assert p1["no_rc"] != 0, (
        f"the role grants nothing on {other}, so that write must be refused; rc="
        f"{p1['no_rc']!r} err={p1['no_err']!r}")
    code, message = _cli_error(p1["no_err"])
    assert code == "AccessDenied", (
        f"the role grants nothing on {other}, so that write must be AccessDenied; got "
        f"{code!r} err={p1['no_err']!r}")
    expected = (f"User: {session} is not authorized to perform: s3:PutObject on resource: "
                f"\"arn:aws:s3:::{other}/{m1}\" because no identity-based policy allows the "
                f"s3:PutObject action")
    assert message == expected, (
        f"AccessDenied message for the write outside the role policy: expected {expected!r}, "
        f"got {message!r}")
    head = s3.head_object(Bucket=allowed, Key=m1)
    assert head["ContentLength"] == len(m1), f"the permitted write must be at S3: {head!r}"
    code = _head_code(s3, other, m1)
    assert code == "404", f"the denied write must have created nothing; HeadObject said {code!r}"

    # An explicit Deny on the permitted bucket's resource policy.
    s3.put_bucket_policy(Bucket=allowed, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Sid": "Sim2realDenyRole", "Effect": "Deny",
                       "Principal": {"AWS": role_arn}, "Action": "s3:PutObject",
                       "Resource": f"arn:aws:s3:::{allowed}/*"}]}))
    ctx.on_cleanup(lambda: s3.delete_bucket_policy(Bucket=allowed))

    # A fresh marker each attempt: an attempt made before the policy is effective legitimately
    # writes, and that object must not be the key the absence assertion reads.
    p2 = _poll(ctx, lambda: _run_probe(ctx, ssm, instance_id,
                                       _probe_script(ctx.region, allowed, other,
                                                     ctx.unique_name("m2-"))),
               lambda p: p["ok_rc"] != 0, 300, 2,
               f"the bucket-policy Deny blocking {role!r} on {allowed}")
    code, message = _cli_error(p2["ok_err"])
    assert code == "AccessDenied", (
        f"an explicit bucket-policy Deny must refuse the write with AccessDenied; rc="
        f"{p2['ok_rc']!r} err={p2['ok_err']!r}")
    expected = (f"User: {session} is not authorized to perform: s3:PutObject on resource: "
                f"\"arn:aws:s3:::{allowed}/{p2['marker']}\" with an explicit deny in a "
                f"resource-based policy")
    assert message == expected, (
        f"AccessDenied message for the bucket-policy Deny: expected {expected!r}, got "
        f"{message!r}")
    assert p2["listed_role"] == role and p2["caller_arn_role"] == role, (
        f"the same role must still be in use; listed={p2['listed_role']!r} "
        f"sts={p2['caller_arn_role']!r}")
    code = _head_code(s3, allowed, p2["marker"])
    assert code == "404", (
        f"the write the bucket policy denied must not exist; HeadObject on {p2['marker']!r} "
        f"said {code!r}")
    kept = s3.head_object(Bucket=allowed, Key=m1)
    assert kept["ETag"] == head["ETag"], (
        f"the object written before the Deny must survive unchanged: {head['ETag']!r} -> "
        f"{kept['ETag']!r}")


def _cli_error(err):
    """(code, message) from the AWS CLI's error report on stderr:
    ``[aws: [ERROR]: ]An error occurred (<Code>) when calling the <Op> operation: <Message>``."""
    line = err.strip()
    head = "An error occurred ("
    at = line.find(head)
    assert at >= 0, f"the CLI did not report a service error; stderr={err!r}"
    code, _, rest = line[at + len(head):].partition(")")
    _, _, message = rest.partition(" operation: ")
    return code, message


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


def _probe_script(region, ok_bucket, no_bucket, marker):
    """One JSON line describing what IMDSv2 served and what those credentials could do. Key
    material never leaves the guest: only a 4-char AccessKeyId prefix is reported."""
    return [
        "set -uo pipefail",
        "IMDS=http://169.254.169.254",
        'T=$(curl -sS -X PUT "$IMDS/latest/api/token" '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300")',
        'H="X-aws-ec2-metadata-token: $T"',
        'ROLE=$(curl -sS -H "$H" "$IMDS/latest/meta-data/iam/security-credentials/" | head -n1)',
        'curl -sS -H "$H" "$IMDS/latest/meta-data/iam/security-credentials/$ROLE" > /tmp/doc.json',
        "python3 - > /tmp/exports.sh <<'PYEXP'",
        "import json",
        "try:",
        '    d = json.load(open("/tmp/doc.json"))',
        "except (OSError, ValueError):",
        "    raise SystemExit(0)",
        'print("export AWS_ACCESS_KEY_ID=%s" % d["AccessKeyId"])',
        'print("export AWS_SECRET_ACCESS_KEY=%s" % d["SecretAccessKey"])',
        'print("export AWS_SESSION_TOKEN=%s" % d["Token"])',
        "PYEXP",
        ". /tmp/exports.sh",
        "rm -f /tmp/exports.sh",
        f"export AWS_DEFAULT_REGION={region}",
        f"echo -n {marker} > /tmp/body",
        "CALLER=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)",
        f"aws s3api put-object --bucket {ok_bucket} --key {marker} --body /tmp/body "
        "> /dev/null 2>/tmp/ok.err; OKRC=$?",
        f"aws s3api put-object --bucket {no_bucket} --key {marker} --body /tmp/body "
        "> /dev/null 2>/tmp/no.err; NORC=$?",
        f"export ROLE OKRC NORC CALLER M={marker}",
        "python3 - <<'PYSUM'",
        "import json, os",
        "def load(p):",
        "    try:",
        "        return json.load(open(p))",
        "    except (OSError, ValueError):",
        "        return {}",
        "def text(p):",
        "    try:",
        "        return open(p).read()[:2000]",
        "    except OSError:",
        '        return ""',
        'd = load("/tmp/doc.json")',
        'caller = os.environ.get("CALLER", "")',
        "print(json.dumps({",
        '    "marker": os.environ["M"], "listed_role": os.environ.get("ROLE", "").strip(),',
        '    "code": d.get("Code", ""), "akid_prefix": d.get("AccessKeyId", "")[:4],',
        '    "caller_arn_role": caller.split("/")[1] if caller.count("/") >= 2 else caller,',
        '    "ok_rc": int(os.environ["OKRC"]), "ok_err": text("/tmp/ok.err"),',
        '    "no_rc": int(os.environ["NORC"]), "no_err": text("/tmp/no.err"),',
        "}))",
        "PYSUM",
        "rm -f /tmp/doc.json",
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
