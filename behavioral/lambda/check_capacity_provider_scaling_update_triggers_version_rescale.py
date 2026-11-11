"""capacity-provider-scaling-update-triggers-version-rescale."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-scaling-update-triggers-version-rescale"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A function version registered under a capacity provider stays correctly listed by
    ListFunctionVersionsByCapacityProvider after the provider's scaling bounds are updated, and
    the new bounds are reflected on the provider itself."""
    lam = ctx.client("lambda")
    net = _create_network(ctx)
    operator_role_arn = _create_operator_role(ctx)
    exec_role_arn = _create_execution_role(ctx)
    cp_name = ctx.unique_name("sim2real-lambda-cp-")

    _create_capacity_provider(
        ctx,
        lam,
        cp_name,
        net,
        operator_role_arn,
        scaling_config={"MaxVCpuCount": 32},
    )
    cp = _wait_cp_active(lam, cp_name, timeout_s=_budget_s(ctx, 600), ctx=ctx)
    cp_arn = cp["CapacityProviderArn"]

    func_name = ctx.unique_name("sim2real-lambda-cp-fn-")
    code_zip = _make_zip("def handler(event, context):\n    return {'ok': True}\n")
    lam.create_function(
        FunctionName=func_name,
        Runtime="python3.13",
        Role=exec_role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": code_zip},
        Architectures=["x86_64"],
        MemorySize=2048,
        CapacityProviderConfig={"LambdaManagedInstancesCapacityProviderConfig": {"CapacityProviderArn": cp_arn}},
    )
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, func_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _wait_function_settled(lam, func_name, timeout_s=_budget_s(ctx, 90), ctx=ctx)

    # Registration under a capacity provider's FunctionVersions list only happens once a version
    # is actually published (per the Lambda Managed Instances getting-started guide) — $LATEST
    # alone is not enough.
    published = lam.publish_version(FunctionName=func_name)
    function_arn = published["FunctionArn"]
    before = _poll_matching_entries(lam, cp_name, function_arn, timeout_s=_budget_s(ctx, 120))
    if not before and _budget_spent(ctx):
        raise TimeoutError(f"function {function_arn} to register under capacity provider {cp_name}: the run budget ended first; not graded")
    assert len(before) >= 1, f"function {function_arn} was not registered under capacity provider {cp_name}"
    assert all(entry["State"] != "Failed" for entry in before)

    lam.update_capacity_provider(
        CapacityProviderName=cp_name,
        CapacityProviderScalingConfig={"MaxVCpuCount": 64},
    )

    # Poll until the new bound is durably applied, then re-check version registration under it.
    deadline = time.monotonic() + _budget_s(ctx, 120)
    new_bound = None
    while True:
        got = lam.get_capacity_provider(CapacityProviderName=cp_name)["CapacityProvider"]
        new_bound = got["CapacityProviderScalingConfig"]["MaxVCpuCount"]
        if new_bound == 64 and got["State"] == "Active":
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("MaxVCpuCount to become 64 with State=Active: the run budget ended first; not graded")
            raise AssertionError(f"MaxVCpuCount never became 64 (last saw {new_bound})")
        time.sleep(1)

    after = _list_matching_entries(lam, cp_name, function_arn)
    assert len(after) == len(before), (
        f"function version membership under capacity provider changed after a scaling update: "
        f"before={before} after={after}"
    )
    assert all(entry["State"] != "Failed" for entry in after)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _list_matching_entries(lam, cp_name, function_arn) -> list:
    base_arn = function_arn.split(":$LATEST")[0]
    resp = lam.list_function_versions_by_capacity_provider(CapacityProviderName=cp_name)
    return [e for e in resp["FunctionVersions"] if e["FunctionArn"].startswith(base_arn)]


def _poll_matching_entries(lam, cp_name, function_arn, timeout_s=120) -> list:
    deadline = time.monotonic() + timeout_s
    while True:
        last = _list_matching_entries(lam, cp_name, function_arn)
        if last or time.monotonic() >= deadline:
            return last
        time.sleep(1)


def _make_zip(handler_source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_source)
    return buf.getvalue()


def _create_network(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.84.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-lambda-cp-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.84.0.0/25",
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-lambda-cp-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-lambda-cp-sg-"),
        Description="sim2real lambda capacity provider test sg",
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": "sim2real-lambda-cp-sg"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return {"subnet_id": subnet_id, "sg_id": sg_id}


def _create_operator_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cp-operator-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cp-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_capacity_provider(ctx, lam, name, net, operator_role_arn, scaling_config=None) -> None:
    kwargs = dict(
        CapacityProviderName=name,
        VpcConfig={"SubnetIds": [net["subnet_id"]], "SecurityGroupIds": [net["sg_id"]]},
        PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
        InstanceRequirements={"Architectures": ["x86_64"]},
    )
    if scaling_config:
        kwargs["CapacityProviderScalingConfig"] = scaling_config

    def _cleanup():
        _delete_capacity_provider_best_effort(lam, name)

    deadline = time.monotonic() + 60
    while True:
        try:
            lam.create_capacity_provider(**kwargs)
            ctx.on_cleanup(_cleanup)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_capacity_provider_best_effort(lam, name) -> None:
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException":
                raise
            last = e
            time.sleep(2)
    raise RuntimeError(f"capacity provider {name} was not deleted: {last!r}")


def _wait_cp_active(lam, name, timeout_s=600, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        cp = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
        last = cp
        if cp["State"] == "Active":
            return cp
        if cp["State"] == "Failed":
            raise AssertionError(f"capacity provider {name} transitioned to Failed: {cp}")
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"capacity provider {name} to reach Active: the run budget ended first; not graded")
    raise AssertionError(f"capacity provider {name} never reached Active (last state: {last})")


def _wait_function_settled(lam, func_name, timeout_s=600, ctx=None) -> str:
    # A Managed-Instances function with no FunctionScalingConfig settles permanently at
    # ActiveNonInvocable (confirmed on real AWS: State holds there with LastUpdateStatus
    # Successful) since this check never invokes it — waiting for exactly "Active" times out
    # forever, not slowly.
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        cfg = lam.get_function_configuration(FunctionName=func_name)
        last = cfg
        if cfg["State"] in ("Active", "ActiveNonInvocable"):
            return cfg["FunctionArn"]
        if cfg["State"] == "Failed":
            raise AssertionError(f"function {func_name} transitioned to Failed: {cfg}")
        if time.monotonic() >= deadline:
            break
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"function {func_name} to settle: the run budget ended first; not graded")
    raise AssertionError(f"function {func_name} never settled (last: {last})")


def _delete_function_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates for a function on its first invocation and never
    deletes. Registered before the function's own teardown, so it runs after the function is
    gone; the service can still create the group from logs it delivers a few seconds later, so
    the group must stay absent across reads spanning 5 s. Only an already-absent group is
    tolerated; a group still present after 30 s raises."""
    import time

    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"

    def present() -> bool:
        found = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
        return any(g["logGroupName"] == group for g in found)

    def stays_absent(span_s: float = 5.0) -> bool:
        until = time.monotonic() + span_s
        while True:
            time.sleep(1.0)
            if present():
                return False
            if time.monotonic() >= until:
                return True

    deadline = time.monotonic() + 30.0
    while True:
        try:
            logs.delete_log_group(logGroupName=group)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if stays_absent():
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
