"""in-vpc-http-get-through-service-network-reaches-lambda-target."""
from __future__ import annotations

import json
import time
import zipfile
import io

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "in-vpc-http-get-through-service-network-reaches-lambda-target"
GROUP = "data-plane"
SERVICES = ["lambda", "vpc-lattice"]

POLL_BUDGET_S = 600.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


#: The target Lambda echoes a per-run nonce baked into the request path, so the body can only
#: come from a real VPC Lattice invocation of this run's function with this request.
_TARGET_HANDLER = """
NONCE = {nonce!r}


def handler(event, context):
    return {{
        "isBase64Encoded": False,
        "statusCode": 200,
        "statusDescription": "200 OK",
        "headers": {{"Content-Type": "text/plain"}},
        "body": NONCE + ":" + event.get("path", ""),
    }}
"""

#: The driver Lambda runs inside the VPC associated to the service network: it is the only
#: thing that can resolve and reach the service's DNS name, which is not routable outside one.
_DRIVER_HANDLER = """
import urllib.error
import urllib.request


def handler(event, context):
    req = urllib.request.Request(event["url"], headers={"Host": event["host"]})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return {"status": resp.status, "body": resp.read().decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": exc.read().decode("utf-8", errors="replace")}
    except Exception as exc:
        return {"status": None, "body": None, "error": f"{type(exc).__name__}: {exc}"}
"""


def _zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, iam, *, vpc: bool) -> str:
    name = ctx.unique_name("sim2real-xsvc-latt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    managed = ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    if vpc:
        managed.append("arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole")
    for arn in managed:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
        ctx.on_cleanup(_teardown(lambda arn=arn: iam.detach_role_policy(RoleName=name, PolicyArn=arn),
                                 "NoSuchEntity"))
    return role_arn


def _create_function(ctx, lam, logs, role_arn, handler_code, *, vpc_config=None) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-xsvc-latt-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    kwargs = dict(
        FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
        Code={"ZipFile": _zip(handler_code)}, Timeout=20, MemorySize=128,
    )
    if vpc_config:
        kwargs["VpcConfig"] = vpc_config
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    resp = None
    last_exc = None
    while resp is None:
        try:
            resp = lam.create_function(**kwargs)
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            if time.monotonic() >= deadline:
                raise AssertionError(f"function never created (IAM propagation?): {last_exc}") from exc
            time.sleep(2)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name, resp["FunctionArn"]


def _poll(get, want, budget_s, what, ctx=None):
    deadline = time.monotonic() + budget_s
    seen = []
    while True:
        seen.append(get())
        if seen[-1] == want:
            return seen[-1]
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what}; statuses seen: {seen[-8:]!r}")
        time.sleep(3)


def _delete_and_wait_gone(delete, get, not_found_code: str, budget_s: float = 180.0):
    """Delete, then poll ``get`` to gone: a dependent service/network delete needs the
    association actually removed, not merely DELETE_IN_PROGRESS."""
    try:
        delete()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != not_found_code:
            raise
        return
    deadline = time.monotonic() + budget_s
    while True:
        try:
            get()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == not_found_code:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"still readable {budget_s:.0f}s after delete, expected {not_found_code}")
        time.sleep(3)


_NET_CIDR = "10.93.0.0/16"
# Lambda refuses a VpcConfig subnet in this zone, so the driver's subnet never lands there.
_NO_LAMBDA_ZONES = {"use1-az3"}


def _own_network(ctx, ec2, made, tag_value):
    """Create the VPC the driver lives in: one subnet and a security group admitting HTTP from it.

    A VPC joins only one service network, so the check associates a VPC of its own. The network
    is removed by the LAST cleanup to run; run() drains the driver's ENI from the subnet first.
    """
    tag_list = [{"Key": "Name", "Value": ctx.unique_name("sim2real-xsvc-latt-net-")},
                {"Key": "sim2real", "Value": tag_value}]
    vpc_id = ec2.create_vpc(CidrBlock=_NET_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag_list}])["Vpc"]["VpcId"]
    made["vpc"] = vpc_id
    ctx.on_cleanup(lambda: _delete_network(ec2, made))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    zones = sorted(
        (z["ZoneId"], z["ZoneName"]) for z in ec2.describe_availability_zones(Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]
        if z["ZoneId"] not in _NO_LAMBDA_ZONES)
    assert zones, "no available availability zone can hold a Lambda VPC subnet"
    made["subnet"] = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_NET_CIDR.replace("/16", "/24"), AvailabilityZone=zones[0][1],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_list}])["Subnet"]["SubnetId"]
    made["sg"] = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-xsvc-latt-sg-"), Description="sim2real lattice driver",
        VpcId=vpc_id, TagSpecifications=[{"ResourceType": "security-group", "Tags": tag_list}],
    )["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=made["sg"], IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": _NET_CIDR}]}])
    return vpc_id, made["subnet"], made["sg"]


def _delete_network(ec2, made, budget_s: float = 240.0):
    """Delete the security group, the subnet and then the VPC; a resource already gone is skipped.

    run() has drained the driver's ENI by now, so a DependencyViolation is a short tail; one that
    outlasts the budget is raised, so a stranded VPC fails the cleanup loudly.
    """
    steps = [
        ("sg", lambda: ec2.delete_security_group(GroupId=made["sg"]), "InvalidGroup.NotFound"),
        ("subnet", lambda: ec2.delete_subnet(SubnetId=made["subnet"]), "InvalidSubnetID.NotFound"),
        ("vpc", lambda: ec2.delete_vpc(VpcId=made["vpc"]), "InvalidVpcID.NotFound"),
    ]
    deadline = time.monotonic() + budget_s
    for key, delete, not_found in steps:
        if not made.get(key):
            continue
        while True:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "DependencyViolation" and time.monotonic() < deadline:
                    time.sleep(10)
                    continue
                if code != not_found:
                    raise
            made.pop(key)
            break


def _drain_driver(ctx, lam, ec2, made, budget_s: float = 1200.0):
    """Delete the driver and wait until Lambda releases its VPC ENI from the subnet.

    DeleteFunction returns before Lambda removes the function's ENI, and until then the subnet
    cannot be deleted. A drain that outlasts the budget returns, and the network cleanup then fails.
    """
    if not made.get("fn") or not made.get("subnet"):
        return
    try:
        lam.delete_function(FunctionName=made["fn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + _budget_s(ctx, budget_s)
    while ec2.describe_network_interfaces(Filters=[
            {"Name": "subnet-id", "Values": [made["subnet"]]}])["NetworkInterfaces"]:
        if time.monotonic() >= deadline:
            return
        time.sleep(5)


def _invoke(lam, name, payload):
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode(), InvocationType="RequestResponse")
    raw = resp["Payload"].read()
    body = json.loads(raw) if raw else None
    return resp.get("FunctionError"), body


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A service network routes an in-VPC HTTP GET through an HTTP listener to its Lambda
    target, and the target's own response body comes back to the caller unchanged.
    """
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    vl = ctx.client("vpc-lattice")
    kv = {"sim2real": "lambda-vpc-lattice-data-plane"}

    made = {}
    vpc_id, subnet_id, sg_id = _own_network(ctx, ec2, made, kv["sim2real"])

    nonce = ctx.unique_name("n")

    try:
        target_role = _create_lambda_role(ctx, iam, vpc=False)
        target_fn, target_arn = _create_function(ctx, lam, logs, target_role, _TARGET_HANDLER.format(nonce=nonce))

        driver_role = _create_lambda_role(ctx, iam, vpc=True)
        driver_fn, _driver_arn = _create_function(
            ctx, lam, logs, driver_role, _DRIVER_HANDLER,
            vpc_config={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
        )
        made["fn"] = driver_fn

        tg = vl.create_target_group(
            name=ctx.unique_name("sim2real-xsvc-latt-tg-"), type="LAMBDA",
            config={"lambdaEventStructureVersion": "V2"}, tags=kv,
        )
        tg_id, tg_arn = tg["id"], tg["arn"]
        ctx.on_cleanup(_teardown(lambda: vl.delete_target_group(targetGroupIdentifier=tg_id),
                                 "ResourceNotFoundException"))
        _poll(lambda: vl.get_target_group(targetGroupIdentifier=tg_id)["status"], "ACTIVE",
              _budget_s(ctx, 120.0), f"target group {tg_id} never reached ACTIVE", ctx=ctx)

        lam.add_permission(
            FunctionName=target_fn, StatementId="AllowVpcLatticeInvoke", Action="lambda:InvokeFunction",
            Principal="vpc-lattice.amazonaws.com", SourceArn=tg_arn,
        )
        registered = vl.register_targets(targetGroupIdentifier=tg_id, targets=[{"id": target_arn}])
        ctx.on_cleanup(_teardown(
            lambda: vl.deregister_targets(targetGroupIdentifier=tg_id, targets=[{"id": target_arn}]),
            "ResourceNotFoundException"))
        assert {t["id"] for t in registered["successful"]} == {target_arn}, (
            f"registering the Lambda target gave successful={registered['successful']!r}"
        )

        net_id = vl.create_service_network(name=ctx.unique_name("sim2real-xsvc-latt-sn-"), authType="NONE",
                                            tags=kv)["id"]
        ctx.on_cleanup(_teardown(lambda: vl.delete_service_network(serviceNetworkIdentifier=net_id),
                                 "ResourceNotFoundException"))

        svc = vl.create_service(name=ctx.unique_name("sim2real-xsvc-latt-svc-"), authType="NONE", tags=kv)
        svc_id = svc["id"]
        ctx.on_cleanup(_teardown(lambda: vl.delete_service(serviceIdentifier=svc_id), "ResourceNotFoundException"))
        _poll(lambda: vl.get_service(serviceIdentifier=svc_id)["status"], "ACTIVE",
              _budget_s(ctx, 120.0), f"service {svc_id} never reached ACTIVE", ctx=ctx)

        listener = vl.create_listener(
            serviceIdentifier=svc_id, name=ctx.unique_name("sim2real-xsvc-latt-lsn-"), protocol="HTTP", port=80,
            defaultAction={"forward": {"targetGroups": [{"targetGroupIdentifier": tg_id}]}}, tags=kv,
        )
        listener_id = listener["id"]
        ctx.on_cleanup(_teardown(
            lambda: vl.delete_listener(serviceIdentifier=svc_id, listenerIdentifier=listener_id),
            "ResourceNotFoundException"))

        assoc_id = vl.create_service_network_service_association(
            serviceNetworkIdentifier=net_id, serviceIdentifier=svc_id, tags=kv
        )["id"]
        ctx.on_cleanup(lambda: _delete_and_wait_gone(
            lambda: vl.delete_service_network_service_association(serviceNetworkServiceAssociationIdentifier=assoc_id),
            lambda: vl.get_service_network_service_association(serviceNetworkServiceAssociationIdentifier=assoc_id),
            "ResourceNotFoundException"))
        _poll(lambda: vl.get_service_network_service_association(
            serviceNetworkServiceAssociationIdentifier=assoc_id)["status"], "ACTIVE",
            _budget_s(ctx, 180.0), f"service network service association {assoc_id} never reached ACTIVE", ctx=ctx)

        vpc_assoc_id = vl.create_service_network_vpc_association(
            serviceNetworkIdentifier=net_id, vpcIdentifier=vpc_id,
            securityGroupIds=[sg_id], tags=kv,
        )["id"]
        ctx.on_cleanup(lambda: _delete_and_wait_gone(
            lambda: vl.delete_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=vpc_assoc_id),
            lambda: vl.get_service_network_vpc_association(serviceNetworkVpcAssociationIdentifier=vpc_assoc_id),
            "ResourceNotFoundException"))
        _poll(lambda: vl.get_service_network_vpc_association(
            serviceNetworkVpcAssociationIdentifier=vpc_assoc_id)["status"], "ACTIVE",
            _budget_s(ctx, 180.0), f"service network VPC association {vpc_assoc_id} never reached ACTIVE", ctx=ctx)

        domain_name = vl.get_service(serviceIdentifier=svc_id)["dnsEntry"]["domainName"]
        path = f"/probe/{nonce}"
        base = f"http://{domain_name}"

        # DNS propagation into the VPC's private hosted zone, and the data-plane route itself, can
        # lag behind the VPC association's own ACTIVE status, so the GET is retried on this run's
        # own nonce rather than treated as settled the instant the control plane says so.
        deadline = time.monotonic() + _budget_s(ctx, POLL_BUDGET_S)
        status, body = None, None
        while True:
            func_error, result = _invoke(lam, driver_fn, {"url": f"{base}{path}", "host": domain_name})
            if not func_error and result is not None:
                status, body = result.get("status"), result.get("body")
                if status == 200:
                    break
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("the in-VPC GET reaching the Lambda target: the run budget "
                                        "ended first; not graded")
                raise AssertionError(
                    f"the in-VPC driver never got a 200 through the service network within the "
                    f"budget; last func_error={func_error!r} result={result!r}"
                )
            time.sleep(3)

        expected_body = f"{nonce}:{path}"
        assert body == expected_body, (
            f"expected the target Lambda's own echo body {expected_body!r}, got {body!r} through "
            f"the service network"
        )
    finally:
        _drain_driver(ctx, lam, ec2, made)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
