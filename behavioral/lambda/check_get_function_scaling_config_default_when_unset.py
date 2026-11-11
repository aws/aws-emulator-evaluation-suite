"""get-function-scaling-config-default-when-unset."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags


CHECK = "get-function-scaling-config-default-when-unset"
GROUP = "server-side"
SERVICES = ["lambda"]

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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFunctionScalingConfig on a Managed Instances version with no PutFunctionScalingConfig
    returns the service-managed RequestedFunctionScalingConfig default (3 minimum, no maximum).
    """
    lam = ctx.client("lambda")
    subnet_id, sg_id = _create_vpc_resources(ctx)
    operator_role_arn = _create_operator_role(ctx)
    cp_name, cp_arn = _create_capacity_provider(ctx, subnet_id, sg_id, operator_role_arn)

    exec_role_arn = _create_exec_role(ctx)
    function_name = ctx.unique_name("sim2real-lambda-mi-fn-")
    _create_function_with_retry(
        ctx,
        function_name=function_name,
        exec_role_arn=exec_role_arn,
        capacity_provider_arn=cp_arn,
    )
    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, function_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    # PublishVersion needs the function out of Pending, which takes a while for Managed Instances
    # while the capacity provider stands up compute; poll PublishVersion itself (bounded).
    version = _poll_publish_version(lam, function_name)

    # AppliedFunctionScalingConfig only appears once execution environments are provisioned
    # (minutes of EC2 launch), so assert the immediately available RequestedFunctionScalingConfig.
    requested = _poll_scaling_config(lam, function_name, version)
    assert requested["MinExecutionEnvironments"] == 3, (
        f"expected the service-managed default MinExecutionEnvironments=3, got {requested}"
    )
    assert "MaxExecutionEnvironments" not in requested, (
        f"expected no MaxExecutionEnvironments in the unset default, got {requested}"
    )


# ===== helpers =====

def _create_vpc_resources(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lambda-cp-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.81.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.81.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real lambda managed-instances capacity provider sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    return subnet_id, sg_id


def _create_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cpop-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN))
    return role_arn


def _create_exec_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-mi-exec-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN))
    return role_arn


def _wait_for_capacity_provider_gone(ctx, name, timeout_s=900.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            lam.get_capacity_provider(CapacityProviderName=name)
        except lam.exceptions.ResourceNotFoundException:
            return
        time.sleep(2)
    raise AssertionError(f"capacity provider {name} was not deleted within {timeout_s}s")


def _call_create_with_retry(lam, kwargs, timeout_s=180.0):
    # A freshly-created operator role can take a few seconds to propagate through IAM
    # before Lambda's cross-service assume-role check will accept it.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_capacity_provider(**kwargs)
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_capacity_provider(ctx, subnet_id, sg_id, operator_role_arn):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lambda-cp-")
    resp = _call_create_with_retry(
        lam,
        {
            "CapacityProviderName": name,
            "VpcConfig": {"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
            "PermissionsConfig": {"CapacityProviderOperatorRoleArn": operator_role_arn},
            "InstanceRequirements": {"Architectures": ["x86_64"]},
        },
    )

    def _cleanup():
        deadline = time.monotonic() + 840.0
        while True:
            try:
                lam.delete_capacity_provider(CapacityProviderName=name)
                break
            except lam.exceptions.ResourceNotFoundException:
                return
            except lam.exceptions.ResourceConflictException:
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)
        _wait_for_capacity_provider_gone(ctx, name, timeout_s=max(1.0, deadline - time.monotonic()))

    ctx.on_cleanup(_cleanup)
    return name, resp["CapacityProvider"]["CapacityProviderArn"]


def _poll_publish_version(lam, function_name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return lam.publish_version(FunctionName=function_name)["Version"]
        except lam.exceptions.ResourceConflictException as exc:
            last_exc = exc
            time.sleep(5)
    raise last_exc


def _poll_scaling_config(lam, function_name, version, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            got = lam.get_function_scaling_config(FunctionName=function_name, Qualifier=version)
            if "RequestedFunctionScalingConfig" not in got:
                raise AssertionError(
                    f"GetFunctionScalingConfig response missing RequestedFunctionScalingConfig, "
                    f"got: {sorted(got.keys())} -> {got}"
                )
            return got["RequestedFunctionScalingConfig"]
        except (lam.exceptions.ResourceNotFoundException, lam.exceptions.ResourceConflictException) as exc:
            last_exc = exc
            time.sleep(5)
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(5)
    raise last_exc


def _simple_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "lambda_function.py",
            "def lambda_handler(event, context):\n    return {'ok': True}\n",
        )
    return buf.getvalue()


def _create_function_with_retry(ctx, function_name, exec_role_arn, capacity_provider_arn, attempts=8):
    lam = ctx.client("lambda")
    last_exc = None
    for _ in range(attempts):
        try:
            return lam.create_function(
                FunctionName=function_name,
                Runtime="python3.13",
                Role=exec_role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": _simple_zip()},
                PackageType="Zip",
                Architectures=["x86_64"],
                MemorySize=2048,
                EphemeralStorage={"Size": 512},
                CapacityProviderConfig={
                    "LambdaManagedInstancesCapacityProviderConfig": {"CapacityProviderArn": capacity_provider_arn}
                },
            )
        except lam.exceptions.InvalidParameterValueException as exc:
            # freshly-created IAM role may not have propagated to Lambda's assume-role check yet
            last_exc = exc
            time.sleep(5)
    raise last_exc


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
