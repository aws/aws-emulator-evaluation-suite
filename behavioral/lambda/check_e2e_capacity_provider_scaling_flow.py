"""e2e-capacity-provider-scaling-flow."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-capacity-provider-scaling-flow"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Managed Instances function on a capacity provider applies its scaling config and invokes;
    after UpdateCapacityProvider shrinks MaxVCpuCount the provider is Active and lists the version.
    """
    lam = ctx.client("lambda")

    network = _create_network(ctx)
    operator_role_arn = _create_operator_role(ctx)
    exec_role_arn = _create_execution_role(ctx)

    cp_name = _create_capacity_provider(ctx, operator_role_arn, network, max_vcpu=32)
    cp = _wait_capacity_provider_state(ctx, cp_name, {"Active", "Failed"})
    assert cp["State"] == "Active", cp
    cp_arn = cp["CapacityProviderArn"]

    function_name = _create_function_on_capacity_provider(ctx, exec_role_arn, cp_arn)
    fn_config = _wait_function_settled(ctx, function_name)
    # With no FunctionScalingConfig yet, a Managed Instances function stays ActiveNonInvocable.
    assert fn_config["State"] in ("Active", "ActiveNonInvocable"), fn_config

    _call_with_retry_on_conflict(
        lambda: lam.publish_version(FunctionName=function_name), timeout_s=_budget(ctx, 180.0)
    )
    version = "1"

    requested_scaling_config = {"MinExecutionEnvironments": 1, "MaxExecutionEnvironments": 4}

    # A just-settled version can reject this with ResourceConflictException for a few seconds.
    put_resp = _call_with_retry_on_conflict(
        lambda: lam.put_function_scaling_config(
            FunctionName=function_name,
            Qualifier=version,
            FunctionScalingConfig=requested_scaling_config,
        ),
        timeout_s=_budget(ctx, 180.0),
    )
    assert put_resp["FunctionState"] in (
        "Pending", "Active", "Deactivating", "Deactivated", "ActiveNonInvocable",
    ), put_resp

    # RequestedFunctionScalingConfig disappears once Applied catches up, so compare Applied
    # against the value requested here.
    scaling = _poll_until(
        lambda: lam.get_function_scaling_config(FunctionName=function_name, Qualifier=version),
        lambda s: s.get("AppliedFunctionScalingConfig") == requested_scaling_config,
        timeout_s=_budget(ctx, 600.0),
        interval_s=2.0,
    )
    assert scaling["AppliedFunctionScalingConfig"] == requested_scaling_config, scaling

    # Force repeated invocations against the published, scaling-configured version.
    for i in range(3):
        resp = lam.invoke(
            FunctionName=function_name,
            Qualifier=version,
            Payload=json.dumps({"i": i}).encode(),
        )
        assert resp["StatusCode"] == 200, f"invoke {i} expected StatusCode 200, got {resp}"
        assert "FunctionError" not in resp, resp

    # Shrink the provider's scaling bounds and confirm it converges back to Active with the new
    # bound applied: the update is asynchronous, so the wait ends on both, or on Failed.
    lam.update_capacity_provider(
        CapacityProviderName=cp_name,
        CapacityProviderScalingConfig={"MaxVCpuCount": 16},
    )
    updated = _poll_until(
        lambda: lam.get_capacity_provider(CapacityProviderName=cp_name)["CapacityProvider"],
        lambda c: (
            c["State"] == "Failed"
            or (
                c["State"] == "Active"
                and c.get("CapacityProviderScalingConfig", {}).get("MaxVCpuCount") == 16
            )
        ),
        timeout_s=_budget(ctx, 900.0),
        interval_s=2.0,
    )
    assert updated["State"] == "Active", updated
    assert updated["CapacityProviderScalingConfig"]["MaxVCpuCount"] == 16, updated

    versions = lam.list_function_versions_by_capacity_provider(CapacityProviderName=cp_name)[
        "FunctionVersions"
    ]
    matching = [v for v in versions if v["FunctionArn"].endswith(f":{version}")]
    assert len(matching) == 1, versions
    assert matching[0]["State"] in ("Active", "Pending"), matching[0]


def _budget(ctx, cap_s, reserve_s=5.0):
    """A wait's cap, cut to the runner's remaining time so the check fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _call_with_retry_on_conflict(fn, *, timeout_s=180.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceConflictException":
                raise
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
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
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
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


def _create_capacity_provider(ctx, operator_role_arn, network, max_vcpu=2):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lmi-cp-")
    deadline = time.monotonic() + 120.0
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
                time.sleep(5.0)
                continue
            raise
    else:
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
                time.sleep(10.0)
                continue
            raise
    raise AssertionError(f"could not delete capacity provider {name} within {timeout_s}s")


def _wait_capacity_provider_state(ctx, name, target_states, timeout_s=900.0, interval_s=2.0):
    lam = ctx.client("lambda")
    return _poll_until(
        lambda: lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"],
        lambda cp: cp["State"] in target_states,
        timeout_s=_budget(ctx, timeout_s),
        interval_s=interval_s,
    )


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_function_on_capacity_provider(ctx, exec_role_arn, capacity_provider_arn):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-lmi-fn-")
    src = "def handler(event, context):\n    return {'ok': True, 'i': event.get('i')}\n"
    deadline = time.monotonic() + 120.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
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
                time.sleep(5.0)
                continue
            raise
    else:
        raise AssertionError(f"create_function never succeeded: {last_err}")

    ctx.on_cleanup(lambda: _delete_function_ignore_missing(ctx, name))
    return name


def _delete_function_ignore_missing(ctx, name):
    lam = ctx.client("lambda")
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_function_settled(ctx, name, timeout_s=600.0, interval_s=2.0):
    lam = ctx.client("lambda")
    config = _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "ActiveNonInvocable", "Failed"),
        timeout_s=_budget(ctx, timeout_s),
        interval_s=interval_s,
    )
    return config


# A resource in this VPC deletes asynchronously: its ENIs linger in the subnet / security group, so
# an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded, one window shared by all of a check's network deletes) for the ENIs to go, retry
# DependencyViolation inside the window, then raise naming the ENIs still attached. Teardown only.
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


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
