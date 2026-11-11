"""deep-lambda-1-fn-state-vpc-attach-in-progress-invoke-allowed-code-update-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-lambda-1-fn-state-vpc-attach-in-progress-invoke-allowed-code-update-rejected"
GROUP = "state-machine"
SERVICES = ["lambda"]

#: How long attaching a VpcConfig to an Active function may stay LastUpdateStatus=InProgress while
#: Lambda provisions the Hyperplane ENIs. A CEILING: the poll returns as soon as it settles.
_ATTACH_CEILING_S = 300
_ACTIVE_CEILING_S = 60
#: Lambda releases a Hyperplane ENI asynchronously after the last function using it is deleted.
_ENI_RELEASE_CEILING_S = 1200


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Attaching a VpcConfig to an Active function keeps it Active and invokable on its code, settles
    LastUpdateStatus Successful with the VPC attached, and a later UpdateFunctionCode is served.
    """
    lam = ctx.client("lambda")
    ec2 = ctx.client("ec2")
    role_arn = _create_vpc_exec_role(ctx)
    vpc_id, subnet_ids, sg_id = _create_vpc_estate(ctx, ec2)

    fn = ctx.unique_name("sim2real-fnstate-attach-")
    _register_log_reap(ctx, [fn])

    # Lambda releases its Hyperplane ENIs minutes after the function is deleted, so a passing run
    # drains the VPC here; after a failure the registered cleanup drains it, so the failure stays
    # the verdict.
    ok = False
    try:
        _scenario(ctx, lam, fn, role_arn, vpc_id, subnet_ids, sg_id)
        ok = True
    finally:
        _delete_function(lam, fn)
        if ok:
            _drain_vpc(ec2, vpc_id, ceiling_s=_ENI_RELEASE_CEILING_S)


def _scenario(ctx, lam, fn, role_arn, vpc_id, subnet_ids, sg_id) -> None:
    _create_function(ctx, lam, fn, role_arn, "v1")
    before = _wait_state(lam, fn, "Active", ceiling_s=_ACTIVE_CEILING_S)
    assert before.get("VpcConfig", {}).get("VpcId", "") == "", (
        f"function must start with no VPC attachment, got {before.get('VpcConfig')!r}"
    )
    # Positive control: the Active, non-VPC function serves v1.
    assert _invoke_marker(lam, fn) == "v1", "positive control: Active function did not serve 'v1'"

    # Attaching a VpcConfig starts an update; reads while it runs depend on how fast the ENIs
    # arrive, so only answers valid in either phase are graded until it settles.
    t0 = time.monotonic()
    resp = lam.update_function_configuration(
        FunctionName=fn, VpcConfig={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]})
    assert resp.get("LastUpdateStatus") in ("InProgress", "Successful"), (
        f"attaching a VpcConfig should start an update, response said "
        f"LastUpdateStatus={resp.get('LastUpdateStatus')!r}"
    )
    mid = lam.get_function_configuration(FunctionName=fn)
    assert mid["State"] == "Active", (
        f"an update must not take an Active function out of Active, got State={mid['State']!r}"
    )
    # Invoke right after the attach is served by the function's code either way.
    served = _invoke_marker(lam, fn)
    assert served == "v1", (
        f"Invoke right after a VPC attach must succeed on the existing code ('v1'), got {served!r}"
    )

    settled = _wait_update_settled(lam, fn, ceiling_s=_ATTACH_CEILING_S)
    print(f"  [{CHECK}] VPC attach settled {settled.get('LastUpdateStatus')} after "
          f"{time.monotonic() - t0:.1f}s")
    assert settled.get("LastUpdateStatus") == "Successful", (
        f"the VPC attach should settle Successful, got {settled.get('LastUpdateStatus')!r} "
        f"({settled.get('LastUpdateStatusReason')!r})"
    )
    assert settled["VpcConfig"]["VpcId"] == vpc_id, (
        f"after the attach settled, VpcConfig is {settled.get('VpcConfig')!r}, expected {vpc_id!r}"
    )
    assert settled["CodeSha256"] == before["CodeSha256"], (
        f"a VpcConfig attach must leave the code unchanged: CodeSha256 moved from "
        f"{before['CodeSha256']!r} to {settled['CodeSha256']!r}"
    )
    assert _invoke_marker(lam, fn) == "v1", "VPC-attached function no longer serves 'v1'"

    # With the attach settled, a code update succeeds.
    lam.update_function_code(FunctionName=fn, ZipFile=_zip_bytes("v2"))
    after = _wait_update_settled(lam, fn, ceiling_s=_ATTACH_CEILING_S)
    assert after.get("LastUpdateStatus") == "Successful", (
        f"post-attach UpdateFunctionCode should settle Successful, got {after!r}"
    )
    served_v2 = _invoke_marker(lam, fn)
    assert served_v2 == "v2", f"after the code update settled, Invoke returned {served_v2!r}"


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
    vpc_id = ec2.create_vpc(CidrBlock="10.41.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _drain_vpc(ec2, vpc_id, ceiling_s=600))
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"need two available AZs in this region, found {zones!r}"
    subnet_ids = []
    for i, zone in enumerate(zones[:2]):
        subnet_ids.append(ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.41.{i}.0/24", AvailabilityZone=zone,
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
