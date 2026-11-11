"""instance-profile-session-userid-is-the-role-id-and-instance-id-composite."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "instance-profile-session-userid-is-the-role-id-and-instance-id-composite"
GROUP = 'identity'
SERVICES = ['ec2', 'sts']

_INSTANCE_RUNNING_TIMEOUT_S = 300.0
_AGENT_ONLINE_TIMEOUT_S = 420.0
_COMMAND_TIMEOUT_S = 180.0
_POLICY_PROPAGATION_TIMEOUT_S = 300.0
_TEARDOWN_TIMEOUT_S = 300.0

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
_INSTANCE_TYPE = "t3.micro"
_VPC_CIDR = "10.83.0.0/16"
_SUBNET_CIDR = "10.83.1.0/24"

_TERMINAL = ("Success", "Cancelled", "TimedOut", "Failed")
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_GONE = ("InvalidInstanceID.NotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
         "InvalidGroup.NotFound", "InvalidInternetGatewayID.NotFound", "NoSuchEntity")

#: A syntactically valid instance id that is NOT the launched instance. The twin statement's
#: condition names this instead, so the two statements differ in exactly one field.
_DECOY_INSTANCE_ID = "i-0decoy00000000000"

_ALLOWED_PREFIX = "allowed"
_DECOY_PREFIX = "decoy"


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Bounded retry that RAISES on timeout. Never a bare sleep."""
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


def _tags(name: str) -> list[dict]:
    return [{"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "instance-profile-userid"}]


def _usable_zone(ec2, region: str) -> str:
    """An AZ that both is available and offers the instance type. No hardcoded zone."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
    )["InstanceTypeOfferings"]}
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in {region} offers {_INSTANCE_TYPE}; offered "
        f"{sorted(offered)!r}, available {sorted(available)!r}"
    )
    return usable[0]


def _build_network(ec2, region: str, name: str, st: dict) -> None:
    """A VPC with one public subnet, reachable enough for the SSM agent to register. Nothing
    ambient is discovered: every id in *st* is created here."""
    st["vpc"] = ec2.create_vpc(
        CidrBlock=_VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags(name)}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[st["vpc"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=st["vpc"], EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=st["vpc"], EnableDnsHostnames={"Value": True})

    st["igw"] = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": _tags(name)}],
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=st["igw"], VpcId=st["vpc"])

    # The main route table of the VPC THIS CHECK JUST CREATED — not an ambient one.
    main_rt = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [st["vpc"]]}])["RouteTables"]
    assert len(main_rt) == 1, (
        f"a freshly created VPC must have exactly one (main) route table; got "
        f"{[r['RouteTableId'] for r in main_rt]!r}"
    )
    ec2.create_route(RouteTableId=main_rt[0]["RouteTableId"],
                     DestinationCidrBlock="0.0.0.0/0", GatewayId=st["igw"])

    zone = _usable_zone(ec2, region)
    st["subnet"] = ec2.create_subnet(
        VpcId=st["vpc"], CidrBlock=_SUBNET_CIDR, AvailabilityZone=zone,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags(name)}],
    )["Subnet"]["SubnetId"]
    ec2.modify_subnet_attribute(SubnetId=st["subnet"],
                                MapPublicIpOnLaunch={"Value": True})

    # The default SG of the created VPC: egress-all, no ingress. That is all the agent needs.
    sgs = [g["GroupId"] for g in ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [st["vpc"]]}])["SecurityGroups"]
        if g["GroupName"] == "default"]
    assert len(sgs) == 1, (
        f"the created VPC must have exactly one default security group; got {sgs!r}"
    )
    st["sg"] = sgs[0]


def _instance_role(iam, name: str) -> tuple[str, str]:
    """A role trusting EC2, able to register with SSM. Returns (RoleId, InstanceProfileName)."""
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav instance-profile aws:userid composite",
        Tags=[{"Key": "sim2real", "Value": "instance-profile-userid"}],
    )["Role"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY)
    iam.create_instance_profile(
        InstanceProfileName=name,
        Tags=[{"Key": "sim2real", "Value": "instance-profile-userid"}])
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    return role["RoleId"], name


def _userid_policy(bucket: str, role_id: str, allowed_instance: str,
                   decoy_instance: str) -> dict:
    """Two statements identical but for the instance id inside the `aws:userid` composite."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowWhenUseridNamesThisInstance",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/{_ALLOWED_PREFIX}/*",
                "Condition": {"StringEquals": {
                    "aws:userid": f"{role_id}:{allowed_instance}"}},
            },
            {
                "Sid": "AllowWhenUseridNamesAnotherInstance",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/{_DECOY_PREFIX}/*",
                "Condition": {"StringEquals": {
                    "aws:userid": f"{role_id}:{decoy_instance}"}},
            },
        ],
    }


def _probe_script(region: str, bucket: str, marker: str) -> list[str]:
    """One JSON line on stdout: the session's own UserId and both PutObject verdicts.

    The API does not reveal which `aws:userid` the guest presented, so the guest reports it.
    """
    return [
        "set -uo pipefail",
        f"REG={region}",
        f"B={bucket}",
        f"M={marker}",
        'UID_=$(aws sts get-caller-identity --query UserId --output text --region "$REG")',
        f'AERR=$(aws s3api put-object --bucket "$B" --key {_ALLOWED_PREFIX}/"$M" '
        '--region "$REG" 2>&1 >/dev/null); ARC=$?',
        f'DERR=$(aws s3api put-object --bucket "$B" --key {_DECOY_PREFIX}/"$M" '
        '--region "$REG" 2>&1 >/dev/null); DRC=$?',
        'printf \'{"userid":"%s","allowed_rc":%s,"allowed_err":"%s",'
        '"decoy_rc":%s,"decoy_err":"%s"}\\n\' '
        '"$UID_" "$ARC" "$(echo "$AERR" | tr -d \'"\\n\')" '
        '"$DRC" "$(echo "$DERR" | tr -d \'"\\n\')"',
    ]


def _run_probe(ssm, instance_id: str, script: list[str]) -> dict:
    """Send the probe and return the JSON object it printed. Raises if the command never lands."""
    sent = _call_with_retry(lambda: ssm.send_command(
        InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
        Parameters={"commands": script}, TimeoutSeconds=int(_COMMAND_TIMEOUT_S),
        Comment="sim2real-behav instance-profile userid probe"))
    command_id = sent["Command"]["CommandId"]

    def _invocation():
        try:
            return ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvocationDoesNotExist":
                return None
            raise

    inv = _poll(_invocation, lambda i: i is not None and i.get("Status") in _TERMINAL,
                timeout_s=_COMMAND_TIMEOUT_S,
                what=f"invocation {command_id} on {instance_id} reaching a terminal status")
    assert inv["Status"] == "Success", (
        f"the probe script itself must run to completion (its own exit status is 0 even when a "
        f"PutObject is denied, because the rc is captured); SSM reports {inv['Status']!r}, "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    lines = [ln for ln in inv["StandardOutputContent"].splitlines() if ln.strip()]
    assert lines, (
        f"the probe printed nothing; stdout={inv['StandardOutputContent']!r} "
        f"stderr={inv.get('StandardErrorContent')!r}"
    )
    return json.loads(lines[-1])


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """DeleteBucket refuses a non-empty bucket, and this check's own PutObject probes always
    leave objects behind on a passing run, so the delete must empty it first."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _wait_gone(ec2, instance_id: str) -> None:
    _poll(
        lambda: [i["State"]["Name"]
                 for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
                 for i in r["Instances"]],
        lambda states: all(s in ("shutting-down", "terminated") for s in states),
        timeout_s=_TEARDOWN_TIMEOUT_S,
        what=f"instance {instance_id} leaving running",
    )


def _teardown(ec2, iam, st: dict, name: str) -> list[str]:
    """Ordered, waiting teardown, IN BAND. Runs every step, then raises what it could not remove,
    naming any failure in flight so it is not masked."""
    left: list[str] = []
    steps: list = []

    def _try(label: str, fn) -> None:
        steps.append((label, fn))

    if st.get("instance"):
        _try(f"terminate {st['instance']}",
             lambda: ec2.terminate_instances(InstanceIds=[st["instance"]]))
        _try(f"await-terminated {st['instance']}", lambda: _wait_gone(ec2, st["instance"]))
    if st.get("subnet"):
        # The instance's ENI must leave the subnet before DeleteSubnet is possible.
        _try("await-eni-drain", lambda: _poll(
            lambda: ec2.describe_network_interfaces(
                Filters=[{"Name": "subnet-id", "Values": [st["subnet"]]}])["NetworkInterfaces"],
            lambda enis: not enis,
            timeout_s=_TEARDOWN_TIMEOUT_S,
            what=f"subnet {st['subnet']} draining its ENIs"))
    if st.get("profile"):
        _try("remove-role-from-profile", lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=st["profile"], RoleName=name))
        _try("delete-instance-profile", lambda: iam.delete_instance_profile(
            InstanceProfileName=st["profile"]))
    if st.get("role"):
        _try("delete-role-policy",
             lambda: iam.delete_role_policy(RoleName=name, PolicyName="userid-conditioned"))
        _try("detach-ssm-core",
             lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_SSM_CORE_POLICY))
        _try("delete-role", lambda: iam.delete_role(RoleName=name))
    if st.get("subnet"):
        _try(f"delete-subnet {st['subnet']}",
             lambda: ec2.delete_subnet(SubnetId=st["subnet"]))
    if st.get("igw"):
        _try("detach-igw", lambda: ec2.detach_internet_gateway(
            InternetGatewayId=st["igw"], VpcId=st["vpc"]))
        _try(f"delete-igw {st['igw']}",
             lambda: ec2.delete_internet_gateway(InternetGatewayId=st["igw"]))
    if st.get("vpc"):
        _try(f"delete-vpc {st['vpc']}", lambda: ec2.delete_vpc(VpcId=st["vpc"]))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _GONE:
                left.append(f"{label}: {exc.response.get('Error', {}).get('Code')}")
        except (AssertionError, WaiterError) as exc:
            # _poll raises AssertionError on timeout and get_waiter raises WaiterError; both are
            # collected so every later step still runs, then raised below.
            left.append(f"{label}: {type(exc).__name__}: {str(exc)[:120]}")
    if left:
        found = sys.exc_info()[1]
        raise AssertionError((f"{found!r}; " if found else "")
                             + f"teardown could not remove everything the check created: {left!r}")
    return left


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EC2 instance-profile session presents `aws:userid` as exactly f"{role_id}:{instance_id}",
    and a policy conditioned on that composite allows PutObject while the same statement naming a
    different instance id denies it until rewritten to the real id.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
    s3 = ctx.client("s3")

    name = ctx.unique_name("sim2real-behav-userid-")
    st: dict = {}

    bucket = ctx.unique_name("sim2real-behav-userid-")
    # Not a region pin: S3 CreateBucket rejects an explicit LocationConstraint of "us-east-1"
    # itself, so the literal here is comparing ctx.region, not choosing where to run.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "instance-profile-userid"}]})

    try:
        _build_network(ec2, ctx.region, name, st)

        role_id, profile = _instance_role(iam, name)
        st["role"] = name
        st["profile"] = profile
        assert role_id.startswith("AROA"), (
            f"CreateRole must return a RoleId this check can use as the first half of the "
            f"composite; got {role_id!r}"
        )

        ami = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
        reservation = _call_with_retry(
            lambda: ec2.run_instances(
                ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
                SubnetId=st["subnet"], SecurityGroupIds=[st["sg"]],
                IamInstanceProfile={"Name": profile},
                TagSpecifications=[{"ResourceType": rt, "Tags": _tags(name)}
                                   for rt in ("instance", "volume")],
            ),
            # A brand-new instance profile is not immediately resolvable by RunInstances.
            codes=_THROTTLE + ("InvalidParameterValue",), retries=30, delay=5.0,
        )
        st["instance"] = reservation["Instances"][0]["InstanceId"]
        instance_id = st["instance"]

        def _instance_states():
            # DescribeInstances can answer InvalidInstanceID.NotFound for a few seconds right
            # after RunInstances returns the id (eventual consistency), the same class _invocation()
            # below tolerates for a fresh SSM command id. Not-yet-visible is not "not running".
            try:
                return [i["State"]["Name"]
                        for r in ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
                        for i in r["Instances"]]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                    return []
                raise

        _poll(
            _instance_states,
            lambda states: states == ["running"],
            timeout_s=_INSTANCE_RUNNING_TIMEOUT_S,
            what=f"instance {instance_id} reaching running",
        )

        # The policy can only be written now: half of the composite is the instance id.
        iam.put_role_policy(
            RoleName=name, PolicyName="userid-conditioned",
            PolicyDocument=json.dumps(
                _userid_policy(bucket, role_id, instance_id, _DECOY_INSTANCE_ID)),
        )

        def _agent():
            for page in ssm.get_paginator("describe_instance_information").paginate():
                for info in page["InstanceInformationList"]:
                    if info.get("InstanceId") == instance_id:
                        return info
            return None

        agent = _poll(_agent, lambda i: i is not None and i.get("PingStatus") == "Online",
                      timeout_s=_AGENT_ONLINE_TIMEOUT_S,
                      what=f"the SSM agent on {instance_id} coming Online")
        assert agent["ResourceType"] == "EC2Instance", (
            f"the side-channel must be a real EC2 instance, SSM reports "
            f"{agent['ResourceType']!r}"
        )

        # --- the headline: the composite the guest actually presents ----------------------
        marker = ctx.unique_name("m-")
        probe = _run_probe(ssm, instance_id,
                           _probe_script(ctx.region, bucket, marker))
        expected_userid = f"{role_id}:{instance_id}"
        assert probe["userid"] == expected_userid, (
            f"an instance-profile session must present aws:userid as "
            f"<role-id>:<ec2-instance-id> = {expected_userid!r}; the guest's own "
            f"GetCallerIdentity reported {probe['userid']!r}"
        )

        # --- the positive control, and the twin refusal, in the same instant --------------
        assert probe["allowed_rc"] == 0, (
            f"the statement conditioned on this instance's own composite must authorize the "
            f"write; the guest's PutObject exited {probe['allowed_rc']!r} with "
            f"{probe['allowed_err']!r}"
        )
        assert probe["decoy_rc"] != 0, (
            f"the twin statement names instance {_DECOY_INSTANCE_ID!r} in its aws:userid "
            f"condition, so this instance's write to {_DECOY_PREFIX}/ must be refused; it exited "
            f"{probe['decoy_rc']!r}"
        )
        # The guest strips double quotes and newlines from the CLI's stderr before printing it.
        expected_denial = (
            f"aws: [ERROR]: An error occurred (AccessDenied) when calling the PutObject operation: "
            f"User: arn:aws:sts::{ctx.account}:assumed-role/{name}/{instance_id} "
            f"is not authorized to "
            f"perform: s3:PutObject on resource: arn:aws:s3:::{bucket}/{_DECOY_PREFIX}/{marker} "
            f"because no identity-based policy allows the s3:PutObject action"
        )
        assert probe["decoy_err"] == expected_denial, (
            f"the refusal must be S3's exact authorization refusal {expected_denial!r}; the guest "
            f"reported {probe['decoy_err']!r}"
        )

        # --- the effect is absent, read independently at the destination ------------------
        head = s3.head_object(Bucket=bucket, Key=f"{_ALLOWED_PREFIX}/{marker}")
        assert head["ContentLength"] == 0, (
            f"the authorized write must be present at S3; HeadObject reports {head!r}"
        )
        denied_code = _s3_head_code(s3, bucket, f"{_DECOY_PREFIX}/{marker}")
        assert denied_code == "404", (
            f"the refused write must have created nothing; HeadObject on "
            f"{_DECOY_PREFIX}/{marker} answered {denied_code!r}"
        )

        # --- restore, then the IDENTICAL call must succeed --------------------------------
        iam.put_role_policy(
            RoleName=name, PolicyName="userid-conditioned",
            PolicyDocument=json.dumps(
                _userid_policy(bucket, role_id, instance_id, instance_id)),
        )
        second_marker = ctx.unique_name("m2-")
        restored = _poll(
            lambda: _run_probe(ssm, instance_id,
                               _probe_script(ctx.region, bucket, second_marker)),
            lambda p: p["decoy_rc"] == 0,
            timeout_s=_POLICY_PROPAGATION_TIMEOUT_S,
            interval_s=15.0,
            what=f"the decoy prefix becoming writable once its aws:userid condition names "
                 f"{instance_id}",
        )
        assert restored["userid"] == expected_userid, (
            f"the composite must be stable across the policy rewrite; got "
            f"{restored['userid']!r}, expected {expected_userid!r}"
        )
        restored_head = s3.head_object(Bucket=bucket, Key=f"{_DECOY_PREFIX}/{second_marker}")
        assert restored_head["ContentLength"] == 0, (
            f"after the condition was rewritten to name this instance, the previously refused "
            f"write must land; HeadObject reports {restored_head!r}"
        )
    finally:
        _teardown(ec2, iam, st, name)


def _s3_head_code(s3, bucket: str, key: str) -> str:
    """The HTTP status HeadObject is refused with; raise if it unexpectedly succeeds."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return str(exc.response.get("Error", {}).get("Code"))
    raise AssertionError(
        f"s3://{bucket}/{key} was expected not to exist and HeadObject found it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
