"""xsvc-ec2-3-lambda-vpc-eni-dependency-violation-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "xsvc-ec2-3-lambda-vpc-eni-dependency-violation-rejected"
GROUP = "vpc-attachment"
SERVICES = ["ec2", "lambda"]

_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
_VPC_CIDR = "10.91.0.0/16"
_SUBNET_CIDR = "10.91.1.0/24"
_SCENARIO = "xsvc-ec2-3-lambda-vpc-eni"

_HANDLER = (
    "def handler(event, context):\n"
    "    return {'sum': sum(event['values']), 'fn': context.function_name}\n"
)


@tags(
    "cap:c3",
    "axis:rejection",
    "concern:negative-classes",
    "concern:e2e",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A VPC Lambda's service-attached ENI pins its security group: DeleteSecurityGroup is
    DependencyViolation while the function exists and it still invokes; after the ENI is released
    the same delete succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    ident = ctx.client("sts").get_caller_identity()
    account, caller = ident["Account"], ident["UserId"].split(":")[0]

    az = _az(ec2)
    vpc = _vpc(ctx, ec2)
    subnet = _subnet(ctx, ec2, vpc, az)
    sg_name = ctx.unique_name("sim2real-xsvc-lvpc-sg-")
    sg = ec2.create_security_group(
        GroupName=sg_name, Description="sim2real-xsvc lambda vpc eni check", VpcId=vpc,
        TagSpecifications=_tags("security-group", sg_name))["GroupId"]
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.delete_security_group(GroupId=sg)))

    role_name = ctx.unique_name("sim2real-xsvc-lvpc-role-")
    role_arn = _role(ctx, iam, role_name)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_VPC_ACCESS_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_VPC_ACCESS_POLICY))

    fn = ctx.unique_name("sim2real-xsvc-lvpc-fn-")
    # Registered BEFORE the function exists, so LIFO reaps the log group AFTER the delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    _create_function_retrying(ctx, lam, fn, role_arn, subnet, sg)

    cfg = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=fn),
                lambda c: c.get("State") in ("Active", "Failed"), 900, 1,
                f"function {fn} leaving Pending")
    assert cfg["State"] == "Active", (
        f"a VPC function with a VPC-access role must reach Active; got State={cfg['State']!r} "
        f"reason={cfg.get('StateReason')!r} code={cfg.get('StateReasonCode')!r}")
    vc = cfg.get("VpcConfig") or {}
    assert vc.get("SubnetIds") == [subnet] and vc.get("SecurityGroupIds") == [sg], (
        f"GetFunctionConfiguration must echo the VpcConfig it was created with; got {vc!r}")
    assert vc.get("VpcId") == vpc, f"VpcConfig.VpcId is {vc.get('VpcId')!r}, expected {vpc!r}"

    # The ENI Lambda created on our behalf, found through EC2 by the group it carries.
    enis = _poll(ctx, lambda: _enis_with_group(ec2, sg), lambda e: len(e) >= 1, 300, 1,
                 f"an ENI carrying {sg} appearing")
    for eni in enis:
        assert eni["SubnetId"] == subnet, (
            f"the function's ENI must be in subnet {subnet!r}; it is in {eni['SubnetId']!r}")
        assert eni["VpcId"] == vpc, f"ENI VpcId {eni['VpcId']!r}, expected {vpc!r}"
        # Lambda's ENI is attached by the service (InstanceOwnerId amazon-aws, a RequesterId from
        # Lambda's own principal) yet reports RequesterManaged False.
        assert eni["InterfaceType"] == "lambda", (
            f"the ENI's InterfaceType must be 'lambda'; got the ENI document {eni!r}")
        assert eni["RequesterManaged"] is False, (
            f"real AWS reports Lambda's ENI with RequesterManaged False; got {eni!r}")
        assert (eni.get("Attachment") or {}).get("InstanceOwnerId") == "amazon-aws", (
            f"the ENI must be attached by the service (InstanceOwnerId amazon-aws); got {eni!r}")
        assert (eni.get("Attachment") or {}).get("Status") == "attached" \
            and eni["Status"] == "in-use", f"the ENI must be attached and in-use; got {eni!r}"
        assert eni.get("RequesterId") and not eni["RequesterId"].endswith(f":{fn}") \
            and caller not in eni["RequesterId"], (
            f"the ENI's RequesterId must name the Lambda service principal that created it, not "
            f"the caller {caller!r}; got {eni.get('RequesterId')!r}")
        assert eni["OwnerId"] == account, (
            f"the ENI must be owned by the function's account {account!r}; got {eni['OwnerId']!r}")
        assert eni["Description"] == f"AWS Lambda VPC ENI-{fn}", (
            f"the ENI's Description must name the function; got {eni['Description']!r}")
        assert [g["GroupId"] for g in eni["Groups"]] == [sg], (
            f"the ENI must carry exactly the function's security group; got {eni['Groups']!r}")
        assert eni["AvailabilityZone"] == az, (
            f"the ENI must be in the subnet's AZ {az!r}; got {eni['AvailabilityZone']!r}")

    # Negative: the ENI still references the group, so EC2 refuses to delete it.
    code = _error(lambda: ec2.delete_security_group(GroupId=sg))
    assert code == ("DependencyViolation", f"resource {sg} has a dependent object"), (
        f"DeleteSecurityGroup on a group a live Lambda ENI references must be rejected with "
        f"DependencyViolation naming the group; got {code!r}")
    still = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"]
    assert [g["GroupId"] for g in still] == [sg], (
        f"the refused delete must leave the group in place; DescribeSecurityGroups returned "
        f"{still!r}")
    after = _enis_with_group(ec2, sg)
    assert {e["NetworkInterfaceId"] for e in after} == {e["NetworkInterfaceId"] for e in enis}, (
        f"the refused delete must not disturb the function's ENIs; before "
        f"{[e['NetworkInterfaceId'] for e in enis]!r}, after "
        f"{[e['NetworkInterfaceId'] for e in after]!r}")

    # Positive control: the function still executes, inside the VPC, on our payload.
    values = [3, 14, 15, 92]
    out = lam.invoke(FunctionName=fn, Payload=json.dumps({"values": values}).encode())
    body = out["Payload"].read().decode()
    assert out["StatusCode"] == 200 and "FunctionError" not in out, (
        f"Invoke must succeed; StatusCode={out['StatusCode']!r} "
        f"FunctionError={out.get('FunctionError')!r} body={body!r}")
    assert json.loads(body) == {"sum": sum(values), "fn": fn}, (
        f"the function must compute over its payload; returned {body!r}")

    # Restore: once the function is gone and its ENI released, the SAME delete succeeds.
    released = _release_function_enis(ctx, lam, ec2, fn, sg)
    assert _enis_with_group(ec2, sg) == [], f"ENIs still carry {sg} after release ({released!r})"
    ec2.delete_security_group(GroupId=sg)
    gone = _error(lambda: ec2.describe_security_groups(GroupIds=[sg]))
    assert gone == ("InvalidGroup.NotFound", f"The security group '{sg}' does not exist"), (
        f"after the function's ENI was released DeleteSecurityGroup must have removed {sg}; "
        f"DescribeSecurityGroups answered {gone!r}")


def _error(fn):
    """The (code, message) of the ClientError fn() raises. RAISES if fn unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"call expected to be refused succeeded: {resp!r}")


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


def _tags(kind, name):
    return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name},
                                            {"Key": "sim2real", "Value": _SCENARIO}]}]


def _retry_dep(fn, budget_s=1500):
    """Teardown delete that waits out Lambda's asynchronous ENI release (DependencyViolation)."""
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


def _az(ec2):
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert zones, "no available availability zone in this region"
    return zones[0]


def _vpc(ctx, ec2):
    name = ctx.unique_name("sim2real-xsvc-lvpc-vpc-")
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=_tags("vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.delete_vpc(VpcId=vpc)))
    try:
        ec2.get_waiter("vpc_available").wait(
            VpcIds=[vpc], WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 600) // 2))})
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"VPC {vpc} available: the run budget ended first; not graded") from None
        raise
    return vpc


def _subnet(ctx, ec2, vpc, az):
    name = ctx.unique_name("sim2real-xsvc-lvpc-sn-")
    sn = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
                           TagSpecifications=_tags("subnet", name))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.delete_subnet(SubnetId=sn)))
    return sn


def _role(ctx, iam, name):
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Description="sim2real-xsvc lambda vpc check",
                          Tags=[{"Key": "sim2real", "Value": _SCENARIO}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", _HANDLER)
    return buf.getvalue()


def _create_function_retrying(ctx, lam, fn, role_arn, subnet, sg, budget_s=180):
    """CreateFunction, retrying (bounded) only while the brand-new role is not yet assumable."""
    deadline = time.time() + _budget_s(ctx, budget_s)
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip()}, Timeout=30, MemorySize=128,
                VpcConfig={"SubnetIds": [subnet], "SecurityGroupIds": [sg]},
                Tags={"sim2real": _SCENARIO})
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if (exc.response["Error"]["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in msg and time.time() < deadline):
                time.sleep(2)
                continue
            if "cannot be assumed" in msg and _budget_spent(ctx):
                raise TimeoutError(f"role {role_arn} assumable by CreateFunction: the run budget ended "
                                   f"first; not graded") from exc
            raise
        ctx.on_cleanup(lambda: _drop_function(lam, fn))
        return


def _enis_with_group(ec2, sg):
    out = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "group-id", "Values": [sg]}]):
        out += page["NetworkInterfaces"]
    return out


def _release_function_enis(ctx, lam, ec2, fn, sg, budget_s=1200):
    """Delete the function, then delete its ENIs once Lambda detaches them; returns their ids.

    After DeleteFunction the ENI turns 'available' minutes later but is not promptly deleted.
    """
    lam.delete_function(FunctionName=fn)
    budget_s = _budget_s(ctx, budget_s)
    deadline = time.monotonic() + budget_s
    detached = set()
    while True:
        enis = _enis_with_group(ec2, sg)
        if not enis:
            return detached
        for e in enis:
            if e["Status"] == "available":
                detached.add(e["NetworkInterfaceId"])
                try:
                    ec2.delete_network_interface(NetworkInterfaceId=e["NetworkInterfaceId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
                        raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the deleted function {fn}'s ENIs released: the run budget ended "
                                   f"first; not graded")
            raise AssertionError(
                f"the deleted function's ENIs never released within {budget_s:.0f}s: "
                f"{[(e['NetworkInterfaceId'], e['Status']) for e in enis]!r}")
        time.sleep(2)


def _drop_function(lam, fn):
    """Teardown delete; the check's own release may already have removed the function."""
    try:
        lam.delete_function(FunctionName=fn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _reap_log_group(logs, name, rounds=4):
    """delete_function leaves /aws/lambda/<fn>, and a late flush can recreate it: reap in a loop."""
    for _ in range(rounds):
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(10)
        if not logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]:
            return
    raise RuntimeError(f"log group {name} kept reappearing")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
