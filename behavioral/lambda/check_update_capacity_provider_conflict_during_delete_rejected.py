"""update-capacity-provider-conflict-during-delete-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-capacity-provider-conflict-during-delete-rejected"
GROUP = "error-semantics"
SERVICES = ["lambda"]

_CP_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_DELETING_CONFLICT_MSG = (
    "The capacity provider can't be updated because it's currently processing another "
    "operation. Wait for the current operation to complete and try again."
)


def _not_found_msg(cp_arn: str) -> str:
    return (
        f"Capacity provider not found: {cp_arn}. Check that the ARN is correct and the "
        "capacity provider exists in this Region."
    )


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider on a provider in State=Deleting is rejected with
    ResourceConflictException and not applied, though the same update succeeded while settled,
    and once the delete completes the identical update returns ResourceNotFoundException."""
    lam = ctx.client("lambda")
    cp_name, cp_arn = _create_capacity_provider(ctx)

    # positive control: update succeeds while the capacity provider is settled
    pre = lam.update_capacity_provider(
        CapacityProviderName=cp_name,
        CapacityProviderScalingConfig={"MaxVCpuCount": 20},
    )["CapacityProvider"]
    assert pre["CapacityProviderScalingConfig"]["MaxVCpuCount"] == 20

    # Give the provider real capacity to tear down: deleting an idle provider completes
    # synchronously, leaving no observable Deleting window to race an update against.
    _attach_and_scale_function(ctx, cp_name, cp_arn)

    # detach: once no function references it, the provider becomes deletable, but the real
    # instances it already launched still take observable time to release.
    _delete_capacity_provider_when_accepted(ctx, lam, cp_name, timeout_s=300.0)

    # The delete above opens the Deleting window, held open while the provider's instances release.
    # The window ends on the service's own clock, so an update that lands after it is answered
    # ResourceNotFoundException; that answer is accepted only once a read shows the provider gone.
    code, msg = _client_error(
        lambda: lam.update_capacity_provider(
            CapacityProviderName=cp_name,
            CapacityProviderScalingConfig={"MaxVCpuCount": 30},
        )
    )
    state = _cp_state(lam, cp_name)
    if code == "ResourceNotFoundException":
        assert state is None, (
            f"UpdateCapacityProvider answered ResourceNotFoundException ({msg!r}) while the "
            f"provider still reads State={state!r}; mid-delete it must be ResourceConflictException"
        )
    else:
        assert code == "ResourceConflictException", (code, msg)
        assert msg == _DELETING_CONFLICT_MSG, (
            f"unexpected mid-delete UpdateCapacityProvider message: {msg!r}"
        )
    assert state in ("Deleting", None), (
        f"after the accepted delete the provider must be Deleting or gone, got {state!r}"
    )

    # effect absent: the rejected 30 value never got applied
    try:
        still = lam.get_capacity_provider(CapacityProviderName=cp_name)["CapacityProvider"]
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", exc.response["Error"]["Code"]
    else:
        assert still["CapacityProviderScalingConfig"]["MaxVCpuCount"] == 20

    # The delete completes, and the identical update then flips from conflict to not found.
    _poll_until(
        lambda: _cp_state(lam, cp_name), lambda s: s is None, timeout_s=900.0, interval_s=1.0, ctx=ctx
    )
    code_after_gone, msg_after_gone = _client_error(
        lambda: lam.update_capacity_provider(
            CapacityProviderName=cp_name,
            CapacityProviderScalingConfig={"MaxVCpuCount": 30},
        )
    )
    assert code_after_gone == "ResourceNotFoundException", (code_after_gone, msg_after_gone)
    assert msg_after_gone == _not_found_msg(cp_arn), (
        f"unexpected UpdateCapacityProvider not-found message: {msg_after_gone!r}"
    )


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=1.0, ctx=None):
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
        raise TimeoutError(f"capacity provider condition (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "lambda_function.py",
            "def lambda_handler(event, context):\n    return {'ok': True}\n",
        )
    return buf.getvalue()


def _create_vpc_resources(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lambda-cp-net-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.92.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.92.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=name,
        Description="sim2real lambda capacity-provider test sg",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return subnet_id, sg_id


def _create_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cp-op-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    # Cleanups run last-in first-out: the policy is detached before the role is deleted.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CP_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_CP_MANAGED_POLICY_ARN))
    return role_arn


def _create_exec_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-cp-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    # Cleanups run last-in first-out: the policy is detached before the role is deleted.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN))
    return role_arn


def _cp_state(lam, name):
    try:
        return lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]["State"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _create_capacity_provider(ctx):
    lam = ctx.client("lambda")
    subnet_id, sg_id = _create_vpc_resources(ctx)
    role_arn = _create_operator_role(ctx)
    name = ctx.unique_name("sim2real-cp-")

    def _try_create():
        try:
            lam.create_capacity_provider(
                CapacityProviderName=name,
                VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
                PermissionsConfig={"CapacityProviderOperatorRoleArn": role_arn},
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return False  # operator role not yet propagated
            raise

    _poll_until(_try_create, lambda ok: ok, timeout_s=120.0, interval_s=2.0, ctx=ctx)

    def _cleanup():
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ResourceConflictException"):
                raise
        _poll_until(lambda: _cp_state(lam, name), lambda s: s is None, timeout_s=600.0, interval_s=3.0)

    ctx.on_cleanup(_cleanup)
    cp = _poll_until(
        lambda: _get_cp_or_none(lam, name), _settled, timeout_s=600.0, interval_s=1.0, ctx=ctx
    )
    return name, cp["CapacityProviderArn"]


def _get_cp_or_none(lam, name):
    try:
        return lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _settled(cp):
    return cp is not None and cp["State"] not in ("Pending",)


def _attach_and_scale_function(ctx, cp_name, cp_arn) -> None:
    """Attach a function to *cp_name* and force nonzero execution environments, so the
    provider has real EC2/ENI capacity to release once the function is removed again."""
    lam = ctx.client("lambda")
    exec_role_arn = _create_exec_role(ctx)
    fn_name = ctx.unique_name("sim2real-cp-fn-")

    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.13",
                Role=exec_role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": _lambda_zip_bytes()},
                MemorySize=2048,
                EphemeralStorage={"Size": 512},
                Architectures=["x86_64"],
                Publish=True,
                CapacityProviderConfig={"LambdaManagedInstancesCapacityProviderConfig": {"CapacityProviderArn": cp_arn}},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                if exc.response["Error"]["Code"] == "InvalidParameterValueException" and _budget_spent(ctx):
                    raise TimeoutError(f"CreateFunction {fn_name} to accept the fresh role: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)

    def _delete_fn_if_needed():
        try:
            lam.delete_function(FunctionName=fn_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn_name))
    ctx.on_cleanup(_delete_fn_if_needed)

    scaling_deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            lam.put_function_scaling_config(
                FunctionName=fn_name,
                Qualifier="1",
                FunctionScalingConfig={"MinExecutionEnvironments": 1, "MaxExecutionEnvironments": 2},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceConflictException" or time.monotonic() > scaling_deadline:
                if exc.response["Error"]["Code"] == "ResourceConflictException" and _budget_spent(ctx):
                    raise TimeoutError("PutFunctionScalingConfig to stop reporting a transient conflict: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)  # the just-published version is not yet ready to accept a scaling config

    arn_suffix = f":{fn_name}:1"
    _poll_until(
        lambda: _function_version_state(lam, cp_name, arn_suffix),
        lambda s: s == "Active",
        timeout_s=900.0,
        interval_s=1.0,
        ctx=ctx,
    )

    lam.delete_function(FunctionName=fn_name)


def _function_version_state(lam, cp_name, arn_suffix):
    versions = lam.list_function_versions_by_capacity_provider(CapacityProviderName=cp_name)["FunctionVersions"]
    match = next((v for v in versions if v["FunctionArn"].endswith(arn_suffix)), None)
    if match is None:
        return None
    if match["State"] == "Failed":
        raise AssertionError(f"function version {arn_suffix} entered Failed state: {match}")
    return match["State"]


def _delete_capacity_provider_when_accepted(ctx, lam, name, timeout_s=300.0) -> None:
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_code = None
    while time.monotonic() < deadline:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "ResourceConflictException":
                raise
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"capacity provider {name} delete to be accepted: the run budget ended first; not graded")
    raise AssertionError(f"capacity provider {name} delete never accepted (last_code={last_code}) within {timeout_s}s")


# AWS-managed ENIs outlive their owner's delete, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait (bounded) for the ENIs to
# go, retry inside the same window, and raise naming the ENIs still attached. The window is shared
# by all network deletes.
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
    """Delete the function's log group, which Lambda can recreate from late log delivery, so it
    must stay absent across two reads 5 s apart; still present after 30 s raises."""
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
