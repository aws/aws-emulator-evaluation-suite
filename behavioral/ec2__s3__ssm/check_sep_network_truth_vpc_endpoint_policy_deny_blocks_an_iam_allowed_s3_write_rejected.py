"""sep-network-truth-vpc-endpoint-policy-deny-blocks-an-iam-allowed-s3-write-rejected."""
from __future__ import annotations

import base64
import json
import re
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-network-truth-vpc-endpoint-policy-deny-blocks-an-iam-allowed-s3-write-rejected"
GROUP = "vpc-endpoint-policy-data-plane"
SERVICES = ["ec2", "s3", "ssm"]

_VPC_CIDR = "10.84.0.0/16"
_SUBNET_CIDR = "10.84.1.0/24"
_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_SCENARIO = "sep-network-truth-vpce-policy"
_CLI_ERROR = re.compile(
    r"An error occurred \(([A-Za-z0-9.]+)\) when calling the (\w+) operation: ([^\n]*)")
# S3 codes that say the request was not decided, so a failed guest call carrying one is retried.
_S3_TRANSIENT = ("RequestTimeout", "InternalError", "SlowDown", "ServiceUnavailable")


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A gateway endpoint policy denying s3:PutObject blocks an in-VPC write that IAM allows (exact
    AccessDenied, no object) while reads still work; resetting the policy makes the write succeed.

    Reference: https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    st: dict = {"instances": [], "sgs": [], "subnets": [], "igws": [], "vpcs": [], "vpce": [],
                "bucket": None}
    # Teardown runs in-band: registered cleanups are time-bounded and cannot wait out instance
    # termination and ENI drain.
    try:
        _build(ctx, ec2, ssm, iam, s3, st)
        _legs(ctx, ec2, ssm, iam, s3, st)
    finally:
        _teardown(ctx, ec2, iam, st, s3)


def _build(ctx, ec2, ssm, iam, s3, st) -> None:
    name = ctx.unique_name("sim2real-sntvpce-")
    st["name"] = name
    region = ctx.region
    st["region"] = region
    st["account"] = ctx.account

    bucket = ctx.unique_name("sim2real-sntvpce-")
    kw = {} if region == "us-east-1" else {
        "CreateBucketConfiguration": {"LocationConstraint": region}}
    s3.create_bucket(Bucket=bucket, **kw)
    st["bucket"] = bucket
    _second_net(ctx, lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": _SCENARIO}]})

    zone = _usable_zones(ec2, want=1)[0]
    vpc = _create_public_vpc(ctx, ec2, st, _VPC_CIDR, name)
    rtb = _main_route_table(ec2, vpc)
    subnet = _create_subnet(ctx, ec2, st, vpc, _SUBNET_CIDR, zone, name)
    sg = _create_sg(ctx, ec2, st, vpc, name + "-client", "sim2real snt vpce client")

    vpce = ec2.create_vpc_endpoint(
        VpcEndpointType="Gateway", VpcId=vpc, ServiceName=f"com.amazonaws.{region}.s3",
        RouteTableIds=[rtb],
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": _tags_for(name)}],
    )["VpcEndpoint"]["VpcEndpointId"]
    st["vpce"].append(vpce)
    _second_net(ctx, lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce]))
    _poll(lambda: _vpce_state(ec2, vpce), lambda s: s == "available",
          timeout_s=_budget_s(ctx, 300), interval_s=1, what=f"gateway endpoint {vpce} available",
          ctx=ctx)
    routes = ec2.describe_route_tables(RouteTableIds=[rtb])["RouteTables"][0]["Routes"]
    pl_routes = [r for r in routes if r.get("GatewayId") == vpce]
    assert len(pl_routes) == 1 and pl_routes[0].get("DestinationPrefixListId", "").startswith("pl-"), (
        f"the endpoint must install exactly one managed prefix-list route in {rtb}: {routes!r}")
    st["vpce_id"] = vpce

    role = name + "-role"
    _create_instance_role(ctx, iam, st, role)
    iam.put_role_policy(RoleName=role, PolicyName="s3-bucket-rw", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
                       "Resource": f"arn:aws:s3:::{bucket}/*"}]}))
    _second_net(ctx, lambda: iam.delete_role_policy(RoleName=role, PolicyName="s3-bucket-rw"))
    st["role_arn"] = iam.get_role(RoleName=role)["Role"]["Arn"]

    ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    st["client"] = _launch(ctx, ec2, st, ami, subnet, sg, name + "-client")
    _wait_online(ctx, ssm, st["client"], "client")


def _guest_s3(ctx, ssm, st, verb, key, payload=""):
    """Run one `aws s3api` call INSIDE the instance. Returns {rc, out, err, code}."""
    b, r = st["bucket"], st["region"]
    if verb == "put":
        cmd = (f"printf '%s' '{payload}' > /tmp/sim2real_payload\n"
               f"aws s3api put-object --bucket {b} --key {key} --body /tmp/sim2real_payload "
               f"--region {r} > /tmp/sim2real_o 2> /tmp/sim2real_e\n")
    else:
        cmd = (f"rm -f /tmp/sim2real_got\n"
               f"aws s3api get-object --bucket {b} --key {key} /tmp/sim2real_got "
               f"--region {r} > /dev/null 2> /tmp/sim2real_e\n"
               "RC0=$?\ncat /tmp/sim2real_got > /tmp/sim2real_o 2>/dev/null || : > /tmp/sim2real_o\n"
               "(exit $RC0)\n")
    script = (
        "set +e\n" + cmd + "RC=$?\n"
        "python3 -c 'import json,sys;print(json.dumps({\"rc\":int(sys.argv[1]),"
        "\"out\":open(\"/tmp/sim2real_o\").read()[-600:],"
        "\"err\":open(\"/tmp/sim2real_e\").read()[-600:]}))' $RC\n")
    res = _run(ctx, ssm, st["client"], script)
    m = _CLI_ERROR.search(res["err"])
    res["code"] = m.group(1) if m else None
    res["message"] = m.group(3) if m else None
    return res


def _host_head_code(s3, bucket, key):
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "exists"


def _legs(ctx, ec2, ssm, iam, s3, st) -> None:
    b, vpce, n = st["bucket"], st["vpce_id"], st["name"]

    # --- L1: full-access endpoint policy -> the write works through the endpoint ------------
    k1 = "k1-" + n
    l1 = _poll(lambda: _guest_s3(ctx, ssm, st, "put", k1, payload=n), lambda r: r["rc"] == 0,
               timeout_s=_budget_s(ctx, 240), interval_s=1,
               what="L1 the guest's first PutObject through the full-access endpoint", ctx=ctx)
    assert l1["code"] is None, f"L1 succeeded yet reported an error: {l1!r}"
    assert _host_head_code(s3, b, k1) == "exists", "L1: the host cannot see the guest's object"

    # --- L2: endpoint policy denies PutObject on this bucket --------------------------------
    deny = {"Version": "2012-10-17", "Statement": [
        {"Sid": "AllowAll", "Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"},
        {"Sid": "DenyPut", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
         "Resource": f"arn:aws:s3:::{b}/*"}]}
    ec2.modify_vpc_endpoint(VpcEndpointId=vpce, PolicyDocument=json.dumps(deny))
    got = json.loads(ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce])["VpcEndpoints"][0][
        "PolicyDocument"])
    assert [s.get("Sid") for s in got["Statement"]] == ["AllowAll", "DenyPut"], (
        f"L2: the endpoint must now carry the deny policy: {got!r}")

    attempts: list = []

    def _try_put():
        key = f"k2-{len(attempts)}-{n}"
        res = _guest_s3(ctx, ssm, st, "put", key, payload=n)
        attempts.append((key, res))
        return key, res
    # A failure with no S3 decision in it (a guest credential fetch or connect timeout) is retried.
    k2, l2 = _poll(_try_put,
                   lambda kr: kr[1]["rc"] != 0 and kr[1]["code"] is not None
                   and kr[1]["code"] not in _S3_TRANSIENT,
                   timeout_s=_budget_s(ctx, 300), interval_s=1,
                   what="L2 the endpoint policy's deny taking effect on the guest's PutObject",
                   ctx=ctx)
    assert l2["code"] == "AccessDenied", (
        f"L2: a write the endpoint policy denies must fail with exactly AccessDenied; the guest "
        f"got rc={l2['rc']!r} code={l2['code']!r} stderr={l2['err']!r}")
    expected_denial = (
        f"User: arn:aws:sts::{st['account']}:assumed-role/{st['role']}/{st['client']} is not "
        f"authorized to perform: s3:PutObject on resource: \"arn:aws:s3:::{b}/{k2}\" with an "
        f"explicit deny in a VPC endpoint policy")
    assert l2["message"] == expected_denial, (
        f"L2: the refusal must carry S3's exact endpoint-policy denial {expected_denial!r}; the "
        f"guest got {l2['message']!r}")
    assert _host_head_code(s3, b, k2) == "404", (
        f"L2: the denied object {k2!r} must not exist; HeadObject said "
        f"{_host_head_code(s3, b, k2)!r}")
    ctrl = _guest_s3(ctx, ssm, st, "get", k1)
    assert ctrl["rc"] == 0 and ctrl["out"] == n, (
        f"L2 positive control: a GetObject the endpoint policy still allows must succeed through "
        f"the same endpoint with the same credentials and return {n!r}; got {ctrl!r}")
    sim = iam.simulate_principal_policy(
        PolicySourceArn=st["role_arn"], ActionNames=["s3:PutObject"],
        ResourceArns=[f"arn:aws:s3:::{b}/{k2}"])["EvaluationResults"]
    assert [r["EvalDecision"] for r in sim] == ["allowed"], (
        f"L2: IAM must still ALLOW the role's write, or L2 proves nothing about the endpoint "
        f"policy: {sim!r}")

    # --- L3: reset the endpoint policy -> the identical write works again -------------------
    ec2.modify_vpc_endpoint(VpcEndpointId=vpce, ResetPolicy=True)
    k3 = "k3-" + n
    l3 = _poll(lambda: _guest_s3(ctx, ssm, st, "put", k3, payload=n), lambda r: r["rc"] == 0,
               timeout_s=_budget_s(ctx, 300), interval_s=1,
               what="L3 the guest's PutObject after the endpoint policy reset", ctx=ctx)
    assert l3["code"] is None, f"L3 succeeded yet reported an error: {l3!r}"
    assert _host_head_code(s3, b, k3) == "exists", (
        f"L3: after the reset the guest's object {k3!r} must exist")
    assert _host_head_code(s3, b, k2) == "404", (
        f"L3: the object denied in L2 must still not exist: {_host_head_code(s3, b, k2)!r}")


# ===== in-band teardown =====================================================
def _teardown(ctx, ec2, iam, st, s3) -> list:
    """Ordered, waiting teardown. Runs every step, then raises naming each one that failed on
    anything but an already-gone code.
    """
    left: list = []
    steps: list = []

    def _step(label, fn):
        steps.append((label, fn))

    if st["instances"]:
        _step("terminate", lambda: ec2.terminate_instances(InstanceIds=list(st["instances"])))
        for iid in st["instances"]:
            _step(f"terminated {iid}", lambda i=iid: _wait_terminated(
                ec2, i, timeout_s=_budget_s(ctx, 420)))
    if st["vpce"]:
        _step("vpce", lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=list(st["vpce"])))
        _step("vpce-gone", lambda: _poll(
            lambda: [e for e in st["vpce"] if _vpce_state(ec2, e) not in ("deleted", "gone")],
            lambda pending: pending == [], timeout_s=_budget_s(ctx, 300), interval_s=2,
            what="the gateway endpoint reporting deleted"))
    for vpc in st["vpcs"]:
        _step(f"eni-drain {vpc}", lambda v=vpc: _poll(
            lambda: _vpc_enis(ec2, v), lambda e: e == [],
            timeout_s=_budget_s(ctx, 300), interval_s=2,
            what=f"every ENI in {v} draining"))
    if st.get("role"):
        _step("role-inline", lambda: iam.delete_role_policy(RoleName=st["role"],
                                                            PolicyName="s3-bucket-rw"))
    if st.get("profile"):
        _step("instance-profile", lambda: _drop_instance_profile(iam, st["profile"], st["role"]))
    if st.get("role"):
        _step("role", lambda: _drop_role(iam, st["role"]))
    for sg in reversed(st["sgs"]):
        _step(f"sg {sg}", lambda s=sg: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=s), timeout_s=_budget_s(ctx, 240)))
    for subnet in st["subnets"]:
        _step(f"subnet {subnet}", lambda s=subnet: _retry_dependency(
            lambda: ec2.delete_subnet(SubnetId=s), timeout_s=_budget_s(ctx, 240)))
    for igw, vpc in st["igws"]:
        _step(f"igw-detach {igw}", lambda g=igw, v=vpc: ec2.detach_internet_gateway(
            InternetGatewayId=g, VpcId=v))
        _step(f"igw {igw}", lambda g=igw: ec2.delete_internet_gateway(InternetGatewayId=g))
    for vpc in st["vpcs"]:
        _step(f"vpc {vpc}", lambda v=vpc: _retry_dependency(
            lambda: ec2.delete_vpc(VpcId=v), timeout_s=_budget_s(ctx, 240)))
    if st.get("bucket"):
        _step(f"bucket {st['bucket']}", lambda: _empty_and_delete_bucket(s3, st["bucket"]))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _GONE_CODES:
                left.append(f"{label}: {code}")
        except Exception as exc:  # noqa: BLE001 - collected, raised below
            left.append(f"{label}: {exc!r}")
    for vpc in st["vpcs"]:
        try:
            still = ec2.describe_vpcs(VpcIds=[vpc])["Vpcs"]
            left.append(f"vpc {vpc} is still describable: {still!r}")
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidVpcID.NotFound":
                left.append(f"vpc {vpc} describe returned {exc.response['Error']['Code']!r}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError((f"{found!r}; " if found else "")
                             + f"teardown could not remove everything the check created: {left!r}")
    return left


def _vpce_state(ec2, vpce):
    try:
        eps = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce])["VpcEndpoints"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "InvalidVpcEndpointId.NotFound":
            return "gone"
        raise
    return eps[0]["State"].lower() if eps else "gone"


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
    s3.delete_bucket(Bucket=bucket)



def _second_net(ctx, fn):
    """Register a non-waiting backup cleanup; not-found is expected after the in-band teardown."""
    def _quiet():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
                raise
    ctx.on_cleanup(_quiet)

_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GONE_CODES = ("NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
               "InvalidGroup.NotFound", "InvalidInstanceID.NotFound",
               "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
               "InvalidVpcEndpointId.NotFound", "NoSuchBucket")



def _tags_for(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": _SCENARIO}]


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, timeout_s, interval_s=1.0, what="", ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what or 'condition'}: the run budget ended first; not graded")
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})")
        time.sleep(interval_s)


def _retry_dependency(fn, timeout_s=240, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DependencyViolation" \
                    and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _usable_zones(ec2, want):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert len(usable) >= want, f"this region offers {_INSTANCE_TYPE} only in {usable!r}"
    return usable[:want]


def _create_public_vpc(ctx, ec2, st, cidr, name):
    """A VPC whose main route table sends 0.0.0.0/0 to its own internet gateway, so each
    instance's SSM agent reaches the public SSM endpoint with no interface endpoints."""
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    st["vpcs"].append(vpc)
    _second_net(ctx, lambda: ec2.delete_vpc(VpcId=vpc))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    igw = ec2.create_internet_gateway(TagSpecifications=[
        {"ResourceType": "internet-gateway", "Tags": _tags_for(name)}])[
        "InternetGateway"]["InternetGatewayId"]
    _second_net(ctx, lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    st["igws"].append((igw, vpc))
    _second_net(ctx, lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc))
    rtb = _main_route_table(ec2, vpc)
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    return vpc


def _main_route_table(ec2, vpc):
    tables = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"]
    assert len(tables) == 1, f"expected one main route table in {vpc}, got {tables!r}"
    return tables[0]["RouteTableId"]


def _create_subnet(ctx, ec2, st, vpc, cidr, zone, name):
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=zone,
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags_for(name)}])["Subnet"]["SubnetId"]
    st["subnets"].append(subnet)
    _second_net(ctx, lambda: ec2.delete_subnet(SubnetId=subnet))
    return subnet


def _create_sg(ctx, ec2, st, vpc, group_name, description):
    sg = ec2.create_security_group(
        GroupName=group_name, Description=description, VpcId=vpc,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_for(group_name)}],
    )["GroupId"]
    st["sgs"].append(sg)
    _second_net(ctx, lambda: ec2.delete_security_group(GroupId=sg))
    return sg


def _create_instance_role(ctx, iam, st, role_name):
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                    Description="sim2real sep-network-truth in-VPC probe",
                    Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    st["role"] = role_name
    _second_net(ctx, lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY)
    _second_net(ctx, lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY))
    iam.create_instance_profile(InstanceProfileName=role_name,
                                Tags=[{"Key": "sim2real", "Value": _SCENARIO}])
    st["profile"] = role_name
    _second_net(ctx, lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    _second_net(ctx, lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=role_name, RoleName=role_name))
    # IAM exposes no "profile usable" condition; _launch's bounded retry on
    # InvalidParameterValue is what makes first use correct.


def _drop_instance_profile(iam, profile, role):
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile, RoleName=role)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    iam.delete_instance_profile(InstanceProfileName=profile)


def _drop_role(iam, role):
    try:
        iam.detach_role_policy(RoleName=role, PolicyArn=_SSM_CORE_POLICY)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    _call_with_retry(lambda: iam.delete_role(RoleName=role), codes=("DeleteConflict",),
                     retries=25, delay=2.0)


def _launch(ctx, ec2, st, ami, subnet, sg, tag_name, user_data=None, private_ip=None):
    nic = {"DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg], "AssociatePublicIpAddress": True}
    if private_ip:
        nic["PrivateIpAddress"] = private_ip
    kwargs = dict(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        NetworkInterfaces=[nic], IamInstanceProfile={"Name": st["profile"]},
        MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
        TagSpecifications=[{"ResourceType": rt, "Tags": _tags_for(tag_name)}
                           for rt in ("instance", "volume", "network-interface")],
    )
    if user_data:
        kwargs["UserData"] = base64.b64encode(user_data.encode()).decode()
    iid = _call_with_retry(lambda: ec2.run_instances(**kwargs),
                           codes=_THROTTLE + ("InvalidParameterValue",), retries=75,
                           delay=2.0)["Instances"][0]["InstanceId"]
    st["instances"].append(iid)
    _second_net(ctx, lambda: ec2.terminate_instances(InstanceIds=[iid]))
    return iid


def _describe_instance(ec2, iid):
    resv = _call_with_retry(lambda: ec2.describe_instances(InstanceIds=[iid]),
                            codes=_THROTTLE + ("InvalidInstanceID.NotFound",), retries=30,
                            delay=2.0)["Reservations"]
    return resv[0]["Instances"][0]


def _wait_terminated(ec2, iid, timeout_s=420):
    _poll(lambda: _describe_instance(ec2, iid)["State"]["Name"], lambda s: s == "terminated",
          timeout_s=timeout_s, interval_s=2, what=f"instance {iid} terminated")


def _vpc_enis(ec2, vpc):
    return [e["NetworkInterfaceId"] for e in ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc]}])["NetworkInterfaces"]]


def _wait_online(ctx, ssm, iid, label):
    def _view():
        infos = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [iid]}])["InstanceInformationList"]
        return infos[0] if infos else None
    info = _poll(_view, lambda i: i is not None and i.get("PingStatus") == "Online",
                 timeout_s=_budget_s(ctx, 720), interval_s=1,
                 what=f"the SSM agent on the {label} {iid} coming Online", ctx=ctx)
    assert info["InstanceId"] == iid, f"SSM answered for the wrong instance: {info!r}"


def _run(ctx, ssm, iid, script, timeout_s=300):
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[iid], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=600,
        Comment="sim2real sep-network-truth probe"),
        codes=_THROTTLE + ("InvalidInstanceId",), retries=75, delay=2.0)
    cid = sent["Command"]["CommandId"]

    def _inv():
        try:
            return ssm.get_command_invocation(CommandId=cid, InstanceId=iid)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise
    inv = _poll(_inv, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=_budget_s(ctx, timeout_s), interval_s=1.0,
                what=f"command {cid} on {iid} finishing", ctx=ctx)
    assert inv["Status"] == "Success" and inv["ResponseCode"] == 0, (
        f"the control command itself failed on {iid}: status={inv['Status']!r} "
        f"rc={inv['ResponseCode']!r} stderr={inv.get('StandardErrorContent')!r}")
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, f"the guest {iid} printed nothing: {inv!r}"
    return json.loads(lines[-1])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
