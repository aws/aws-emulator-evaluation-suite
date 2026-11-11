"""scaling-config-roundtrip."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scaling-config-roundtrip"
GROUP = "state-machine"
SERVICES = ["lambda"]


# Prefixes the failure for a resource the control plane accepted that never reached its ready state.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A function scaling config set by PutFunctionScalingConfig on a Lambda Managed Instances
    function version is returned by GetFunctionScalingConfig."""
    lam = ctx.client("lambda")
    fn_name, version = _setup_managed_instances_function(ctx)

    put = _call_with_retry(
        lambda: lam.put_function_scaling_config(
            FunctionName=fn_name,
            Qualifier=version,
            FunctionScalingConfig={"MinExecutionEnvironments": 1, "MaxExecutionEnvironments": 2},
        ),
        description="put_function_scaling_config waiting on published-version readiness",
        retryable=("ResourceConflictException",),
        timeout_s=180.0,
    )
    assert put["FunctionState"] in (
        "Pending",
        "Active",
        "Failed",
        "Deactivating",
        "Deactivated",
        "ActiveNonInvocable",
        "Deleting",
    ), f"unexpected FunctionState from PutFunctionScalingConfig: {put['FunctionState']!r}"

    got = _poll_until(
        lambda: lam.get_function_scaling_config(FunctionName=fn_name, Qualifier=version),
        lambda cfg: cfg.get("RequestedFunctionScalingConfig", {}).get("MaxExecutionEnvironments") == 2,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert got["RequestedFunctionScalingConfig"]["MaxExecutionEnvironments"] == 2, (
        f"expected MaxExecutionEnvironments=2, got {got['RequestedFunctionScalingConfig']!r}"
    )
    assert got["RequestedFunctionScalingConfig"]["MinExecutionEnvironments"] == 1, (
        f"expected MinExecutionEnvironments=1, got {got['RequestedFunctionScalingConfig']!r}"
    )
    assert got["FunctionArn"].endswith(f":{version}") or got["FunctionArn"].endswith(fn_name), (
        f"GetFunctionScalingConfig FunctionArn {got['FunctionArn']!r} names neither "
        f"{fn_name!r} nor qualifier {version!r}"
    )


# ===== helpers =====
def _call_with_retry(fn, *, description, retryable=("InvalidParameterValueException",), timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in retryable:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"{description}: still failing after {timeout_s}s: {last_exc}") from last_exc


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context):\n    return {'ok': True}\n")
    return buf.getvalue()


def _setup_managed_instances_function(ctx):
    """Create a capacity provider plus a Lambda Managed Instances function attached to
    it; any failure along this path fails the check."""
    lam = ctx.client("lambda")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    try:
        vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16")["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

        azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
        subnet_ids = []
        for i, az in enumerate(azs):
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.91.{i}.0/24", AvailabilityZone=az
            )["Subnet"]["SubnetId"]
            subnet_ids.append(subnet_id)
            ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))

        sg_name = ctx.unique_name("sim2real-behav-scsg-")
        sg = ec2.create_security_group(
            GroupName=sg_name,
            Description="sim2real scaling-config behavioral check",
            VpcId=vpc_id,
            TagSpecifications=[
                {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}
            ],
        )
        sg_id = sg["GroupId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

        operator_role_name = ctx.unique_name("sim2real-behav-scoprole-")
        exec_role_name = ctx.unique_name("sim2real-behav-screxec-")
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
        operator_role = iam.create_role(RoleName=operator_role_name, AssumeRolePolicyDocument=json.dumps(trust))
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=operator_role_name))
        ec2_policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
        iam.attach_role_policy(RoleName=operator_role_name, PolicyArn=ec2_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=operator_role_name, PolicyArn=ec2_policy_arn))

        exec_role = iam.create_role(RoleName=exec_role_name, AssumeRolePolicyDocument=json.dumps(trust))
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_role_name))
        exec_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy_arn))

        cp_name = ctx.unique_name("sim2real-behav-sccp-")
        cp = _call_with_retry(
            lambda: lam.create_capacity_provider(
                CapacityProviderName=cp_name,
                VpcConfig={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
                PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role["Role"]["Arn"]},
                InstanceRequirements={"Architectures": ["x86_64"]},
                CapacityProviderScalingConfig={"MaxVCpuCount": 32},
            ),
            description="create_capacity_provider waiting on IAM role propagation",
        )["CapacityProvider"]
        ctx.on_cleanup(lambda: _delete_cp(lam, cp_name))

        active = _poll_until(
            lambda: lam.get_capacity_provider(CapacityProviderName=cp_name)["CapacityProvider"],
            lambda p: p["State"] in ("Active", "Failed"),
            timeout_s=240.0,
            interval_s=5.0,
        )
        if active["State"] != "Active":
            raise _never_ready(
                f"capacity provider did not become Active: {active.get('StateReason')}",
            )

        fn_name = ctx.unique_name("sim2real-behav-scfn-")
        lam.create_function(
            FunctionName=fn_name,
            Runtime="python3.13",
            Role=exec_role["Role"]["Arn"],
            Handler="lambda_function.handler",
            Code={"ZipFile": _lambda_zip_bytes()},
            Timeout=10,
            MemorySize=2048,
            Publish=False,
            CapacityProviderConfig={
                "LambdaManagedInstancesCapacityProviderConfig": {"CapacityProviderArn": cp["CapacityProviderArn"]}
            },
        )
        ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn_name))
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

        # ActiveNonInvocable is a legitimate terminal state here, not a transient one: with no
        # scaling config set yet, MinExecutionEnvironments defaults to 0, so the function has zero
        # warm environments and stays ActiveNonInvocable indefinitely (it does not
        # converge to Active within 280s). It becomes invocable only once scaling config requests
        # capacity, which is the very call this check makes next.
        fn_cfg = _poll_until(
            lambda: lam.get_function_configuration(FunctionName=fn_name),
            lambda cfg: cfg["State"] in ("Active", "ActiveNonInvocable", "Failed"),
            timeout_s=180.0,
            interval_s=5.0,
        )
        if fn_cfg["State"] == "Failed":
            raise _never_ready(f"function {fn_name} entered Failed: {fn_cfg.get('StateReason')}")
        version = lam.publish_version(FunctionName=fn_name)["Version"]
        return fn_name, version
    except AssertionError:
        raise
    except Exception as e:  # noqa: BLE001 - brand-new preview infra is a prerequisite, not a bug
        raise AssertionError(f"Lambda Managed Instances / scaling config prerequisites unavailable: {e}") from e


def _delete_cp(lam, name: str) -> None:
    """Delete the capacity provider, retrying the conflict AWS returns while it still settles."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached; every other error propagates. The window is shared by all of one
# check's network deletes and fits the suite's cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across two reads 5 s apart. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5.0)
        if not present():
            time.sleep(5.0)
            if not present():
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
