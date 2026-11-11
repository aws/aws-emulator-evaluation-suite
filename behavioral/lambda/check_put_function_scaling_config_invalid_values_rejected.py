"""put-function-scaling-config-invalid-values-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-function-scaling-config-invalid-values-rejected"
GROUP = "overly-permissive"
SERVICES = ["lambda"]

# A function without a capacity-provider configuration rejects ANY PutFunctionScalingConfig body
# with AccessDeniedException, so value validation is only reachable on a capacity-provider function.
_INVALID_REJECTION_CODES = {"InvalidParameterValueException", "ValidationException"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a capacity-provider function, a valid Min<=Max FunctionScalingConfig is accepted but
    Min>Max is rejected, and GetFunctionScalingConfig still shows the accepted config.
    """
    lam = ctx.client("lambda")
    if not hasattr(lam, "put_function_scaling_config"):
        raise AssertionError("unreachable: PutFunctionScalingConfig not present in installed boto3 lambda model")

    subnet_id, sg_id = _create_vpc_resources(ctx)
    operator_role_arn = _create_operator_role(ctx)
    cp_name, cp_arn = _create_capacity_provider(ctx, subnet_id, sg_id, operator_role_arn)
    exec_role_arn = _create_exec_role(ctx)
    function_name, version = _create_scaling_eligible_function(ctx, exec_role_arn, cp_arn)

    # Positive control: separates "rejects invalid values" from "rejects everything".
    _put_scaling_config_with_retry(
        lam, function_name, version, {"MinExecutionEnvironments": 1, "MaxExecutionEnvironments": 5}
    )
    applied = _poll_scaling_config(lam, function_name, version)
    assert applied["MinExecutionEnvironments"] == 1, applied
    assert applied["MaxExecutionEnvironments"] == 5, applied

    def _attempt_invalid() -> None:
        lam.put_function_scaling_config(
            FunctionName=function_name,
            Qualifier=version,
            FunctionScalingConfig={"MinExecutionEnvironments": 5, "MaxExecutionEnvironments": 2},
        )

    code, message = _error(_attempt_invalid)
    assert code in _INVALID_REJECTION_CODES, f"expected one of {_INVALID_REJECTION_CODES}, got {code!r}"
    if code == "InvalidParameterValueException":
        assert message == (
            "Invalid function scaling configuration. Min execution environments should be lower "
            "or equal than Max execution environments."
        ), message

    # Effect-absent: an independent read (Get, not Put) shows the requested config is still the
    # positive control's -- the rejected write never landed.
    still = lam.get_function_scaling_config(FunctionName=function_name, Qualifier=version)
    requested = still["RequestedFunctionScalingConfig"]
    assert requested["MinExecutionEnvironments"] == 1, requested
    assert requested["MaxExecutionEnvironments"] == 5, requested

    _teardown_scaling_infra(ctx, lam, function_name, cp_name)


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Run *fn*, which AWS must refuse; return the refusal's (code, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"PutFunctionScalingConfig accepted MinExecutionEnvironments > MaxExecutionEnvironments: {result!r}"
    )


def _create_vpc_resources(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lambda-cp-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.82.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.82.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real lambda managed-instances capacity provider sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return subnet_id, sg_id


_OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _create_operator_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cpop-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    # Cleanup runs LIFO: the detach registered after the delete runs before it.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN))
    return role_arn


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    # Cleanup runs LIFO: the detach registered after the delete runs before it.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN))
    return role_arn


def _create_capacity_provider(ctx, subnet_id, sg_id, operator_role_arn):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lambda-cp-")

    deadline = time.monotonic() + 60.0
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_capacity_provider(
                CapacityProviderName=name,
                VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
                PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
                InstanceRequirements={"Architectures": ["x86_64"]},
                CapacityProviderScalingConfig={"MaxVCpuCount": 16, "ScalingMode": "Auto"},
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # freshly-attached operator-role policy may not have propagated yet
            last_exc = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"unreachable: CreateCapacityProvider kept rejecting the operator role: {last_exc}")

    def _cleanup():
        _delete_capacity_provider_and_confirm_gone(lam, name)

    ctx.on_cleanup(_cleanup)
    return name, resp["CapacityProvider"]["CapacityProviderArn"]


def _delete_capacity_provider_and_confirm_gone(lam, name, request_timeout_s=120.0, confirm_timeout_s=300.0):
    # Two independent budgets, so a slow delete request cannot starve the confirmation phase.
    request_deadline = time.monotonic() + request_timeout_s
    while time.monotonic() < request_deadline:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
        except lam.exceptions.ResourceNotFoundException:
            return
        except lam.exceptions.ResourceConflictException:
            time.sleep(5)
            continue
        break
    confirm_deadline = time.monotonic() + confirm_timeout_s
    while time.monotonic() < confirm_deadline:
        try:
            lam.get_capacity_provider(CapacityProviderName=name)
        except lam.exceptions.ResourceNotFoundException:
            return
        time.sleep(5)
    raise AssertionError(
        f"capacity provider {name} was not confirmed deleted within {confirm_timeout_s}s of disappearance-confirmation"
    )


def _zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_scaling_eligible_function(ctx, exec_role_arn, cp_arn):
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-lambda-mi-fn-")
    code_bytes = _zip_bytes("def handler(event, context):\n    return {'ok': True}\n")

    deadline = time.monotonic() + 60.0
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.13",
                Role=exec_role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": code_bytes},
                MemorySize=2048,
                EphemeralStorage={"Size": 512},
                Architectures=["x86_64"],
                Publish=True,
                Tags={"sim2real:managed": "true"},
                CapacityProviderConfig={
                    "LambdaManagedInstancesCapacityProviderConfig": {"CapacityProviderArn": cp_arn}
                },
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # role propagation delay
            last_exc = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"unreachable: CreateFunction kept rejecting the execution role: {last_exc}")

    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, function_name))
    ctx.on_cleanup(lambda: _delete_function_if_present(lam, function_name))
    return function_name, resp["Version"]


def _delete_function_if_present(lam, function_name):
    try:
        lam.delete_function(FunctionName=function_name)
    except lam.exceptions.ResourceNotFoundException:
        pass


def _put_scaling_config_with_retry(lam, function_name, version, scaling_config, timeout_s=120.0):
    # Right after Publish the version can still be mid-provisioning, which surfaces as a
    # transient ResourceConflictException on this setup call.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            lam.put_function_scaling_config(
                FunctionName=function_name, Qualifier=version, FunctionScalingConfig=scaling_config
            )
            return
        except lam.exceptions.ResourceConflictException as exc:
            last_exc = exc
            time.sleep(2)
    raise AssertionError(f"unreachable: PutFunctionScalingConfig kept reporting a transient conflict: {last_exc}")


def _poll_scaling_config(lam, function_name, version, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            got = lam.get_function_scaling_config(FunctionName=function_name, Qualifier=version)
            if "RequestedFunctionScalingConfig" in got:
                return got["RequestedFunctionScalingConfig"]
            last_exc = AssertionError(f"missing RequestedFunctionScalingConfig: {got}")
        except lam.exceptions.ResourceConflictException as exc:
            last_exc = exc
        time.sleep(5)
    raise last_exc


def _teardown_scaling_infra(ctx, lam, function_name, cp_name):
    # Deleted in the body rather than in on_cleanup: a capacity provider's EC2/ENI teardown
    # routinely needs more time than the cleanup budget allows.
    lam.delete_function(FunctionName=function_name)
    _delete_capacity_provider_and_confirm_gone(lam, cp_name)


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
