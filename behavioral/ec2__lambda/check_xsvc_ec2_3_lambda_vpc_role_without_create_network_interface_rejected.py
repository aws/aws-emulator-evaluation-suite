"""xsvc-ec2-3-lambda-vpc-role-without-create-network-interface-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "xsvc-ec2-3-lambda-vpc-role-without-create-network-interface-rejected"
GROUP = "vpc-attachment-permission"
SERVICES = ["ec2", "lambda"]

_BASIC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_VPC_ACCESS_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
_VPC_CIDR = "10.92.0.0/16"
_SUBNET_CIDR = "10.92.1.0/24"
_SCENARIO = "xsvc-ec2-3-lambda-vpc-perm"
_ENI_MSG = ("The provided execution role does not have permissions to call "
            "CreateNetworkInterface on EC2")

_HANDLER = (
    "def handler(event, context):\n"
    "    return {'product': event['a'] * event['b']}\n"
)


@tags(
    "cap:c3",
    "cap:c7",
    "axis:rejection",
    "concern:negative-classes",
    "concern:e2e",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """VPC CreateFunction is InvalidParameterValueException, leaving no function or ENI, when the role
    lacks ec2:CreateNetworkInterface; attaching AWSLambdaVPCAccessExecutionRole makes it succeed.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    az = _az(ec2)
    vpc = _vpc(ctx, ec2)
    subnet = _subnet(ctx, ec2, vpc, az)
    sg_name = ctx.unique_name("sim2real-xsvc-lperm-sg-")
    sg = ec2.create_security_group(
        GroupName=sg_name, Description="sim2real-xsvc lambda vpc permission check", VpcId=vpc,
        TagSpecifications=_tags("security-group", sg_name))["GroupId"]
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.delete_security_group(GroupId=sg)))

    role_name = ctx.unique_name("sim2real-xsvc-lperm-role-")
    role_arn = _role(ctx, iam, role_name)
    # Logs only: everything a non-VPC function needs, and no ec2:CreateNetworkInterface.
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_POLICY))

    fn = ctx.unique_name("sim2real-xsvc-lperm-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))

    # Lambda evaluates the execution role's EC2 permissions at create time.
    err = _create_error(ctx, lam, fn, role_arn, subnet, sg)
    assert err["Code"] == "InvalidParameterValueException", (
        f"CreateFunction with a role lacking ec2:CreateNetworkInterface must be rejected with "
        f"InvalidParameterValueException; got {err!r}")
    assert err.get("Message") == _ENI_MSG, (
        f"the rejection must name the missing CreateNetworkInterface permission exactly; message "
        f"was {err.get('Message')!r}")
    absent = _error(lambda: lam.get_function(FunctionName=fn))
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    assert absent == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"the refused create must leave no function behind; GetFunction answered {absent!r}")
    stray = _enis_with_group(ec2, sg)
    assert stray == [], (
        f"the refused create must leave no ENI carrying {sg}; found "
        f"{[e['NetworkInterfaceId'] for e in stray]!r}")

    # Repair exactly the one broken thing, on the same role.
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_VPC_ACCESS_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_VPC_ACCESS_POLICY))
    _create_after_repair(ctx, lam, fn, role_arn, subnet, sg)

    cfg = _poll(ctx, lambda: lam.get_function_configuration(FunctionName=fn),
                lambda c: c.get("State") in ("Active", "Failed"), 900, 1,
                f"function {fn} leaving Pending")
    assert cfg["State"] == "Active", (
        f"with AWSLambdaVPCAccessExecutionRole attached the function must reach Active; got "
        f"State={cfg['State']!r} reason={cfg.get('StateReason')!r}")
    assert (cfg.get("VpcConfig") or {}).get("SubnetIds") == [subnet], (
        f"the accepted function must be attached to {subnet!r}; VpcConfig={cfg.get('VpcConfig')!r}")
    enis = _poll(ctx, lambda: _enis_with_group(ec2, sg), lambda e: len(e) >= 1, 300, 1,
                 f"an ENI carrying {sg} appearing")
    assert all(e["SubnetId"] == subnet and e["InterfaceType"] == "lambda"
               and (e.get("Attachment") or {}).get("InstanceOwnerId") == "amazon-aws"
               for e in enis), (
        f"the repaired function's ENIs must be Lambda-type, service-attached, in {subnet!r}; "
        f"got {enis!r}")

    out = lam.invoke(FunctionName=fn, Payload=json.dumps({"a": 37, "b": 41}).encode())
    body = out["Payload"].read().decode()
    assert out["StatusCode"] == 200 and "FunctionError" not in out, (
        f"Invoke of the repaired function must succeed; StatusCode={out['StatusCode']!r} "
        f"FunctionError={out.get('FunctionError')!r} body={body!r}")
    assert json.loads(body) == {"product": 37 * 41}, f"the function returned {body!r}"

    # Once the function is gone and its ENI released, the group deletes.
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
    name = ctx.unique_name("sim2real-xsvc-lperm-vpc-")
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
    name = ctx.unique_name("sim2real-xsvc-lperm-sn-")
    sn = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
                           TagSpecifications=_tags("subnet", name))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dep(lambda: ec2.delete_subnet(SubnetId=sn)))
    return sn


def _role(ctx, iam, name):
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Description="sim2real-xsvc lambda vpc permission check",
                          Tags=[{"Key": "sim2real", "Value": _SCENARIO}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("index.py", _HANDLER)
    return buf.getvalue()


def _create(lam, fn, role_arn, subnet, sg):
    return lam.create_function(
        FunctionName=fn, Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip()}, Timeout=30, MemorySize=128,
        VpcConfig={"SubnetIds": [subnet], "SecurityGroupIds": [sg]},
        Tags={"sim2real": _SCENARIO})


def _create_error(ctx, lam, fn, role_arn, subnet, sg, budget_s=180):
    """The error a create expected to be REFUSED returns, retrying only while the new role is not
    yet assumable (a different rejection that must not be mistaken for the one under test). If
    the create unexpectedly succeeds, register its teardown and raise."""
    deadline = time.time() + _budget_s(ctx, budget_s)
    while True:
        try:
            resp = _create(lam, fn, role_arn, subnet, sg)
        except ClientError as exc:
            e = exc.response["Error"]
            if "cannot be assumed" in e.get("Message", "") and time.time() < deadline:
                time.sleep(2)
                continue
            if "cannot be assumed" in e.get("Message", "") and _budget_spent(ctx):
                raise TimeoutError(f"role {role_arn} assumable by CreateFunction: the run budget ended "
                                   f"first; not graded") from exc
            return e
        ctx.on_cleanup(lambda: _drop_function(lam, fn))
        raise AssertionError(f"CreateFunction expected to be refused succeeded: {resp!r}")


def _create_after_repair(ctx, lam, fn, role_arn, subnet, sg, budget_s=240):
    """CreateFunction after the policy attach, retrying (bounded) only while IAM propagation
    still shows the role as lacking the permission. Raises if it never succeeds."""
    deadline = time.time() + _budget_s(ctx, budget_s)
    while True:
        try:
            _create(lam, fn, role_arn, subnet, sg)
        except ClientError as exc:
            e = exc.response["Error"]
            if (e["Code"] == "InvalidParameterValueException" and e.get("Message") == _ENI_MSG
                    and time.time() < deadline):
                time.sleep(2)
                continue
            if (e["Code"] == "InvalidParameterValueException" and e.get("Message") == _ENI_MSG
                    and _budget_spent(ctx)):
                raise TimeoutError(f"the VPC-access policy on {role_arn} effective for CreateFunction: "
                                   f"the run budget ended first; not graded") from exc
            raise AssertionError(f"CreateFunction after attaching the VPC-access policy failed: {e!r}")
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
