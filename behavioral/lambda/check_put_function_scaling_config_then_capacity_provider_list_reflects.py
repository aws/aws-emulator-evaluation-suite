"""put-function-scaling-config-then-capacity-provider-list-reflects."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-function-scaling-config-then-capacity-provider-list-reflects"
GROUP = "server-side"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A published, scaling-configured capacity-provider function version appears in
    ListFunctionVersionsByCapacityProvider with no registration call, and its scaling config applies.
    """
    lam = ctx.client("lambda")

    network = _create_network(ctx)
    operator_role_arn = _create_operator_role(ctx)
    exec_role_arn = _create_execution_role(ctx)

    cp_name = _create_capacity_provider(ctx, operator_role_arn, network)
    cp = _wait_capacity_provider_state(ctx, cp_name, {"Active", "Failed"})
    assert cp["State"] == "Active", cp
    cp_arn = cp["CapacityProviderArn"]

    # Before anything is published, the provider must not report our not-yet-existing version.
    before = lam.list_function_versions_by_capacity_provider(CapacityProviderName=cp_name)[
        "FunctionVersions"
    ]
    before_arns = {v["FunctionArn"] for v in before}

    function_name = _create_function_on_capacity_provider(ctx, exec_role_arn, cp_arn)
    fn_config = _wait_function_active(ctx, function_name)
    # A function created with CapacityProviderConfig reports ActiveNonInvocable for $LATEST: only
    # a version registered with the capacity provider is invocable.
    assert fn_config["State"] == "ActiveNonInvocable", fn_config

    lam.publish_version(FunctionName=function_name)
    version = "1"

    versioned_arn = f"{fn_config['FunctionArn']}:{version}"
    assert versioned_arn not in before_arns

    # MinExecutionEnvironments=0 is rejected unless MaxExecutionEnvironments is also 0, so a nonzero
    # ceiling needs a nonzero floor. Right after PublishVersion, PutFunctionScalingConfig can
    # transiently answer ResourceConflictException while the version settles -- bounded retry.
    _put_scaling_config_retrying(
        ctx, lam, function_name, version,
        {"MinExecutionEnvironments": 1, "MaxExecutionEnvironments": 2},
    )

    # No separate registration call exists -- the list must reflect it automatically.
    after = _poll_until(
        lambda: lam.list_function_versions_by_capacity_provider(CapacityProviderName=cp_name)[
            "FunctionVersions"
        ],
        lambda vs: any(v["FunctionArn"] == versioned_arn for v in vs),
        timeout_s=600.0,
        interval_s=2.0,
        ctx=ctx,
    )
    matching = [v for v in after if v["FunctionArn"] == versioned_arn]
    assert len(matching) == 1, after
    assert matching[0]["State"] in ("Pending", "Active"), matching[0]

    # Once a request is fully applied, "RequestedFunctionScalingConfig" is omitted from the
    # response entirely; its absence, not equality with Applied, is the convergence signal.
    requested_applied = _poll_until(
        lambda: lam.get_function_scaling_config(FunctionName=function_name, Qualifier=version),
        lambda s: "RequestedFunctionScalingConfig" not in s,
        timeout_s=600.0,
        interval_s=2.0,
        ctx=ctx,
    )
    assert requested_applied["AppliedFunctionScalingConfig"] == {
        "MinExecutionEnvironments": 1,
        "MaxExecutionEnvironments": 2,
    }, requested_applied



def _put_scaling_config_retrying(ctx, lam, function_name, qualifier, config, timeout_s=120.0):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_err = None
    while time.monotonic() < deadline:
        try:
            lam.put_function_scaling_config(
                FunctionName=function_name, Qualifier=qualifier, FunctionScalingConfig=config
            )
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "ResourceConflictException":
                time.sleep(2.0)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError("PutFunctionScalingConfig to stop reporting a transient conflict: the run budget ended first; not graded")
    raise AssertionError(f"put_function_scaling_config never succeeded: {last_err}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=2.0, ctx=None):
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"Lambda managed-instances condition (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _lambda_trust_policy():
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_operator_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lmi-operator-")
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_lambda_trust_policy())["Role"]
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=name, PolicyArn="arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lmi-exec-")
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=_lambda_trust_policy())["Role"]
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    tag_name = ctx.unique_name("sim2real-lmi-net-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.78.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.78.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=tag_name,
        Description="sim2real lambda managed instances test sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": tag_name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id}


def _create_capacity_provider(ctx, operator_role_arn, network, max_vcpu=16):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lmi-cp-")
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last_err = None
    while time.monotonic() < deadline:
        try:
            lam.create_capacity_provider(
                CapacityProviderName=name,
                VpcConfig={
                    "SubnetIds": [network["subnet_id"]],
                    "SecurityGroupIds": [network["sg_id"]],
                },
                PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
                InstanceRequirements={"Architectures": ["x86_64"]},
                CapacityProviderScalingConfig={"MaxVCpuCount": max_vcpu},
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidParameterValueException", "ResourceConflictException"):
                time.sleep(2.0)
                continue
            raise
    else:
        if _budget_spent(ctx):
            raise TimeoutError("CreateCapacityProvider to be accepted: the run budget ended first; not graded")
        raise AssertionError(f"create_capacity_provider never succeeded: {last_err}")

    ctx.on_cleanup(lambda: _delete_capacity_provider_retrying(ctx, name))
    return name


def _delete_capacity_provider_retrying(ctx, name, timeout_s=300.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceConflictException":
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not delete capacity provider {name} within {timeout_s}s")


def _wait_capacity_provider_state(ctx, name, target_states, timeout_s=900.0, interval_s=2.0):
    lam = ctx.client("lambda")
    return _poll_until(
        lambda: lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"],
        lambda cp: cp["State"] in target_states,
        timeout_s=timeout_s,
        interval_s=interval_s,
        ctx=ctx,
    )


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_function_on_capacity_provider(ctx, exec_role_arn, capacity_provider_arn):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lmi-fn-")
    src = "def handler(event, context):\n    return {'ok': True}\n"
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last_err = None
    while time.monotonic() < deadline:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.13",
                Role=exec_role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _zip_bytes(src)},
                Architectures=["x86_64"],
                MemorySize=2048,
                Timeout=30,
                CapacityProviderConfig={
                    "LambdaManagedInstancesCapacityProviderConfig": {
                        "CapacityProviderArn": capacity_provider_arn,
                    }
                },
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidParameterValueException", "ResourceConflictException"):
                time.sleep(2.0)
                continue
            raise
    else:
        if _budget_spent(ctx):
            raise TimeoutError("CreateFunction to be accepted: the run budget ended first; not graded")
        raise AssertionError(f"create_function never succeeded: {last_err}")

    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
    ctx.on_cleanup(lambda: _delete_function_ignore_missing(ctx, name))
    return name


def _delete_function_ignore_missing(ctx, name):
    lam = ctx.client("lambda")
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_function_active(ctx, name, timeout_s=600.0, interval_s=2.0):
    lam = ctx.client("lambda")
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "ActiveNonInvocable", "Failed"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        ctx=ctx,
    )


# Resources in a VPC delete asynchronously: their ENIs linger in the subnet / security group, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry DependencyViolation in the same window, then raise naming the
# ENIs still attached. The window is shared by all of one check's network deletes.
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
        _time.sleep(3)
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
        _time.sleep(3)


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
