"""deep-lambda-1-fn-state-vpc-create-pending-rejects-invoke-and-update."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-1-fn-state-vpc-create-pending-rejects-invoke-and-update"
GROUP = "state-machine"
SERVICES = ["lambda"]

#: How long a VPC-attached function may sit in Pending while Lambda provisions its Hyperplane
#: ENIs. A CEILING, not a sleep: the poll returns the moment State leaves Pending.
_ACTIVE_CEILING_S = 300
#: A non-VPC function has no ENI to provision; it gets the ordinary short budget.
_TWIN_ACTIVE_CEILING_S = 60
#: Lambda releases a Hyperplane ENI asynchronously after the last function using it is deleted,
#: and the subnets / security group cannot be deleted until it is gone.
_ENI_RELEASE_CEILING_S = 1200


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateFunction with VpcConfig reports State Pending (Creating); the function then becomes
    Active with its VPC attachment and serves Invoke and UpdateFunctionConfiguration, and a non-VPC
    twin created alongside it becomes Active and serves Invoke.
    """
    lam = ctx.client("lambda")
    ec2 = ctx.client("ec2")
    role_arn = _create_vpc_exec_role(ctx)
    vpc_id, subnet_ids, sg_id = _create_vpc_estate(ctx, ec2)

    vpc_fn = ctx.unique_name("sim2real-fnstate-vpc-")
    twin_fn = ctx.unique_name("sim2real-fnstate-twin-")
    _register_log_reap(ctx, [vpc_fn, twin_fn])

    # Lambda releases its Hyperplane ENIs minutes after the function is deleted, so a passing run
    # drains the VPC here; after a failure the registered cleanup drains it, so the failure stays
    # the verdict.
    ok = False
    try:
        _scenario(ctx, lam, vpc_fn, twin_fn, role_arn, vpc_id, subnet_ids, sg_id)
        ok = True
    finally:
        _delete_function(lam, vpc_fn)
        _delete_function(lam, twin_fn)
        if ok:
            _drain_vpc(ec2, vpc_id, ceiling_s=_ENI_RELEASE_CEILING_S)


def _scenario(ctx, lam, vpc_fn, twin_fn, role_arn, vpc_id, subnet_ids, sg_id) -> None:
    created = _create_function(
        ctx, lam, vpc_fn, role_arn, "vpc-v1",
        VpcConfig={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
    )
    t_created = time.monotonic()
    _create_function(ctx, lam, twin_fn, role_arn, "twin-v1")
    assert created["VpcConfig"]["VpcId"] == vpc_id, (
        f"CreateFunction echoed VpcConfig {created.get('VpcConfig')!r}, expected VpcId {vpc_id!r}"
    )

    # The create response itself reports Pending; later reads depend on how fast the ENIs arrive.
    assert created["State"] == "Pending", (
        f"CreateFunction of a VPC function must report State 'Pending'; got "
        f"State={created.get('State')!r} StateReasonCode={created.get('StateReasonCode')!r}"
    )
    assert created.get("StateReasonCode") == "Creating", (
        f"the Pending create response should report StateReasonCode 'Creating', got "
        f"{created.get('StateReasonCode')!r}"
    )

    # Twin control: the non-VPC function created at the same moment becomes Active and invokable.
    twin_cfg = _wait_state(lam, twin_fn, "Active", ceiling_s=_TWIN_ACTIVE_CEILING_S)
    assert twin_cfg.get("VpcConfig", {}).get("VpcId", "") == "", (
        f"twin must have no VPC attachment, got {twin_cfg.get('VpcConfig')!r}"
    )
    twin_out = _invoke_marker(lam, twin_fn)
    assert twin_out == "twin-v1", f"twin invoke returned marker {twin_out!r}, expected 'twin-v1'"

    # Pending -> Active, under its own ceiling.
    active = _wait_state(lam, vpc_fn, "Active", ceiling_s=_ACTIVE_CEILING_S)
    print(f"  [{CHECK}] VPC function Pending -> Active after {time.monotonic() - t_created:.1f}s")
    assert active["VpcConfig"]["VpcId"] == vpc_id, (
        f"Active function lost its VPC attachment: {active.get('VpcConfig')!r}"
    )
    assert sorted(active["VpcConfig"]["SubnetIds"]) == sorted(subnet_ids), (
        f"Active function subnets {active['VpcConfig'].get('SubnetIds')!r} != {sorted(subnet_ids)!r}"
    )

    # Once Active, Invoke and UpdateFunctionConfiguration succeed.
    vpc_out = _invoke_marker(lam, vpc_fn)
    assert vpc_out == "vpc-v1", f"Active VPC function returned marker {vpc_out!r}, expected 'vpc-v1'"
    lam.update_function_configuration(FunctionName=vpc_fn, Description="after-active")
    settled = _wait_update_settled(lam, vpc_fn, ceiling_s=_ACTIVE_CEILING_S)
    assert settled.get("LastUpdateStatus") == "Successful", (
        f"UpdateFunctionConfiguration on an Active function should settle Successful, got "
        f"{settled.get('LastUpdateStatus')!r} ({settled.get('LastUpdateStatusReason')!r})"
    )
    assert settled.get("Description") == "after-active", (
        f"Description after the post-Active update is {settled.get('Description')!r}"
    )


def _zip_bytes(marker: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", f"def handler(event, context):\n    return {{'marker': {marker!r}}}\n")
    return buf.getvalue()


def _create_vpc_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fnstate-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    # IAM propagation is absorbed at first use by the deadline-bound
    # InvalidParameterValueException retry in _create_function.
    return role["Role"]["Arn"]


def _create_vpc_estate(ctx, ec2):
    tag = [{"Key": "sim2real", "Value": CHECK},
           {"Key": "Name", "Value": ctx.unique_name("sim2real-fnstate-")}]
    vpc_id = ec2.create_vpc(CidrBlock="10.40.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _drain_vpc(ec2, vpc_id, ceiling_s=600))
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"need two available AZs in this region, found {zones!r}"
    subnet_ids = []
    for i, zone in enumerate(zones[:2]):
        subnet_ids.append(ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.40.{i}.0/24", AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}])["Subnet"]["SubnetId"])
    sg_id = ec2.create_security_group(
        VpcId=vpc_id, GroupName=ctx.unique_name("sim2real-fnstate-sg-"),
        Description="sim2real fn-state check", TagSpecifications=[
            {"ResourceType": "security-group", "Tags": tag}])["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _create_function(ctx, lam, name, role_arn, marker, **extra):
    deadline = time.monotonic() + 120
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip_bytes(marker)}, MemorySize=128, Timeout=10,
                Tags={"sim2real": CHECK}, **extra)
            break
        except ClientError as exc:
            # IAM propagation of a just-created role (assume, or the VPC ENI permissions).
            if (exc.response["Error"]["Code"] == "InvalidParameterValueException"
                    and time.monotonic() < deadline):
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_function(lam, name))
    return resp


def _delete_function(lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _register_log_reap(ctx, names):
    """Registered BEFORE the functions exist so LIFO runs it after their deletes; repeated because
    a buffered log stream can recreate the group after one delete."""
    logs = ctx.client("logs")

    def _reap():
        for _ in range(3):
            for n in names:
                try:
                    logs.delete_log_group(logGroupName=f"/aws/lambda/{n}")
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            time.sleep(4)

    ctx.on_cleanup(_reap)


def _wait_state(lam, name, want, *, ceiling_s):
    deadline = time.monotonic() + ceiling_s
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == want:
            return cfg
        if cfg["State"] == "Failed":
            raise AssertionError(f"{name} entered Failed: {cfg.get('StateReason')!r}")
        time.sleep(2)
    raise AssertionError(f"{name} did not reach State {want!r} within {ceiling_s}s; last {cfg!r}")


def _wait_update_settled(lam, name, *, ceiling_s):
    deadline = time.monotonic() + ceiling_s
    cfg = None
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg.get("LastUpdateStatus") != "InProgress":
            return cfg
        time.sleep(2)
    raise AssertionError(f"{name} update still InProgress after {ceiling_s}s; last {cfg!r}")


def _invoke_marker(lam, name):
    resp = lam.invoke(FunctionName=name, Payload=b"{}")
    body = json.loads(resp["Payload"].read())
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"invoke of {name} failed: StatusCode={resp['StatusCode']!r} body={body!r}"
    )
    return body.get("marker")


def _drain_vpc(ec2, vpc_id, *, ceiling_s):
    """Wait for Lambda to release its ENIs (deleting any left 'available'), then delete the
    security groups, subnets and the VPC; a VPC already gone is clean, every other error raises."""
    deadline = time.monotonic() + ceiling_s
    try:
        while True:
            enis = []
            for page in ec2.get_paginator("describe_network_interfaces").paginate(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
                enis.extend(page["NetworkInterfaces"])
            if not enis:
                break
            for eni in enis:
                if eni["Status"] == "available":
                    try:
                        ec2.delete_network_interface(NetworkInterfaceId=eni["NetworkInterfaceId"])
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in (
                                "InvalidNetworkInterfaceID.NotFound", "InvalidNetworkInterface.InUse"):
                            raise
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"Lambda ENIs in {vpc_id} not released within {ceiling_s}s: "
                    f"{[(e['NetworkInterfaceId'], e['Status']) for e in enis]!r}")
            time.sleep(2)
        for sg in ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["SecurityGroups"]:
            if sg["GroupName"] != "default":
                ec2.delete_security_group(GroupId=sg["GroupId"])
        for sn in ec2.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]:
            ec2.delete_subnet(SubnetId=sn["SubnetId"])
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
