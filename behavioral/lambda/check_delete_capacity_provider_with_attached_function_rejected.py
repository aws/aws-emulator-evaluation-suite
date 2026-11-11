"""delete-capacity-provider-with-attached-function-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-capacity-provider-with-attached-function-rejected"
GROUP = "server-side"
SERVICES = ["lambda"]

_OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"
_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _attached_conflict_msg(version_arn: str) -> str:
    return (
        "The capacity provider is currently in use by 1 function. To delete this capacity "
        f"provider, first remove its association with {version_arn}."
    )


def _not_found_msg(cp_arn: str) -> str:
    return (
        f"Capacity provider not found: {cp_arn}. Check that the ARN is correct and the "
        "capacity provider exists in this Region."
    )


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCapacityProvider with a function version attached is rejected with
    ResourceConflictException and leaves the provider Active; after detaching it succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_DeleteCapacityProvider.html
    """
    subnet_id, sg_id = _create_vpc_resources(ctx)
    subnet_ids = [subnet_id]
    lam = ctx.client("lambda")

    operator_role_arn = _create_operator_role(ctx)
    exec_role_arn = _create_exec_role(ctx)

    cp_name = ctx.unique_name("sim2real-neg-cp-")
    _create_capacity_provider_with_retry(
        lam,
        timeout_s=_budget_s(ctx, 60.0),
        ctx=ctx,
        CapacityProviderName=cp_name,
        VpcConfig={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
        PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
        InstanceRequirements={"Architectures": ["x86_64"]},
        # AWS rejects MaxVCpuCount below its recommended minimum of 16 for this feature.
        CapacityProviderScalingConfig={"MaxVCpuCount": 16, "ScalingMode": "Auto"},
        Tags={"sim2real:managed": "true"},
    )
    cp_deleted = False
    ctx.on_cleanup(lambda: None if cp_deleted else _delete_capacity_provider_when_empty(ctx, cp_name))
    cp = _wait_capacity_provider_state(ctx, cp_name, {"Active"}, timeout_s=_budget_s(ctx, 600.0))
    cp_arn = cp["CapacityProviderArn"]

    fn_name = ctx.unique_name("sim2real-neg-cp-fn-")
    fn_arn = _create_function_with_retry(
        ctx,
        FunctionName=fn_name,
        # python3.12 is rejected outright for a Managed-Instances (CapacityProviderConfig) function.
        Runtime="python3.13",
        Role=exec_role_arn,
        Handler="lambda_function.lambda_handler",
        Code={"ZipFile": _lambda_zip_bytes()},
        MemorySize=2048,
        EphemeralStorage={"Size": 512},
        Architectures=["x86_64"],
        Publish=True,
        CapacityProviderConfig={
            "LambdaManagedInstancesCapacityProviderConfig": {"CapacityProviderArn": cp_arn}
        },
        Tags={"sim2real:managed": "true"},
    )["FunctionArn"]
    fn_deleted = False

    def _delete_fn_if_needed():
        if not fn_deleted:
            lam.delete_function(FunctionName=fn_name)

    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, fn_name))
    ctx.on_cleanup(_delete_fn_if_needed)

    # A version requesting zero desired execution environments never provisions and sits in
    # Pending forever; request at least one so it actually settles to Active. The version can
    # still be mid-provisioning right after Publish, which the API surfaces as a transient
    # ResourceConflictException; retry that specific, bounded condition rather than sleeping
    # blindly before the call.
    _put_function_scaling_config_with_retry(
        lam,
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        FunctionName=fn_name,
        Qualifier="1",
        FunctionScalingConfig={"MinExecutionEnvironments": 1, "MaxExecutionEnvironments": 2},
    )
    arn_suffix = f":{fn_name}:1"
    _wait_function_version_state(ctx, cp_name, arn_suffix, {"Active"}, timeout_s=_budget_s(ctx, 900.0))

    # Break exactly one thing: try to delete the provider while still attached.
    code, msg = _client_error(lambda: lam.delete_capacity_provider(CapacityProviderName=cp_name))
    assert code == "ResourceConflictException", (
        f"expected ResourceConflictException, got {code!r} ({msg!r})"
    )
    assert msg == _attached_conflict_msg(f"{fn_arn}:1"), (
        f"unexpected DeleteCapacityProvider message: {msg!r}"
    )

    # Effect absent: the provider is still there and still governs the version.
    still_there = lam.get_capacity_provider(CapacityProviderName=cp_name)["CapacityProvider"]
    assert still_there["State"] != "Deleting"
    versions = lam.list_function_versions_by_capacity_provider(CapacityProviderName=cp_name)[
        "FunctionVersions"
    ]
    assert any(v["FunctionArn"].endswith(arn_suffix) for v in versions)

    # Positive control: remove the attachment, then the identical call succeeds.
    lam.delete_function(FunctionName=fn_name)
    fn_deleted = True
    _delete_capacity_provider_when_empty(ctx, cp_name, timeout_s=_budget_s(ctx, 600.0))
    cp_deleted = True

    # DeleteCapacityProvider is asynchronous (accepted, then the provider moves to Deleting
    # and disappears in the background) -- an immediate single read races that and can still
    # find it present. Bound the wait for the independent read to return the specific
    # not-found code rather than checking exactly once.
    final_code, final_msg = _poll_for_error(
        lambda: lam.get_capacity_provider(CapacityProviderName=cp_name),
        {"ResourceNotFoundException"},
        timeout_s=_budget_s(ctx, 300.0),
        ctx=ctx,
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {final_code!r}"
    )
    assert final_msg == _not_found_msg(cp_arn), f"unexpected GetCapacityProvider message: {final_msg!r}"

    # The dead id is also unusable for a mutation, not just for reads.
    update_code, update_msg = _client_error(
        lambda: lam.update_capacity_provider(
            CapacityProviderName=cp_name,
            CapacityProviderScalingConfig={"MaxVCpuCount": 32, "ScalingMode": "Auto"},
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateCapacityProvider on the deleted provider to fail with "
        f"ResourceNotFoundException, got {update_code!r}"
    )
    assert update_msg == _not_found_msg(cp_arn), (
        f"unexpected UpdateCapacityProvider message: {update_msg!r}"
    )



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


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
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.93.1.0/24",
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


def _create_operator_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-neg-cp-operator-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_OPERATOR_POLICY_ARN)
    return role_arn


def _create_exec_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-neg-cp-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    return role_arn


def _create_capacity_provider_with_retry(lam, timeout_s: float = 60.0, ctx=None, **kwargs) -> dict:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_capacity_provider(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            # A just-attached operator-role policy can take a few seconds to become visible
            # to CreateCapacityProvider's own validation; retry that specific, transient
            # condition rather than a bare sleep before the call. A just-created security group
            # is likewise refused as invalid until it propagates to Lambda's validation.
            if code == "InvalidParameterValueException" and (
                "operator role" in msg or "security group IDs are invalid" in msg
            ):
                last_exc = exc
                time.sleep(1)
                continue
            raise
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("CreateCapacityProvider to accept the new role and security group: the run budget ended first; not graded")
    raise AssertionError(f"create_capacity_provider never succeeded within {timeout_s}s: {last_exc}")


def _put_function_scaling_config_with_retry(lam, timeout_s: float = 120.0, ctx=None, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            lam.put_function_scaling_config(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceConflictException":
                raise
            last_exc = exc
            time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("PutFunctionScalingConfig to stop reporting a transient conflict: the run budget ended first; not graded")
    raise AssertionError(f"put_function_scaling_config never succeeded within {timeout_s}s: {last_exc}")


def _poll_for_error(fn, terminal_codes: set, *, timeout_s: float, interval_s: float = 1.0, ctx=None):
    """(code, message) once fn raises one of terminal_codes; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
            last = None
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = (err.get("Code", ""), err.get("Message", ""))
            if last[0] in terminal_codes:
                return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"one of {sorted(terminal_codes)} (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"no {sorted(terminal_codes)} within {timeout_s}s (last={last!r})")


def _create_function_with_retry(ctx, timeout_s: float = 30.0, **kwargs) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"create_function never succeeded within {timeout_s}s: {last_exc}")


def _wait_capacity_provider_state(ctx, name: str, target_states: set, timeout_s: float) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        cp = lam.get_capacity_provider(CapacityProviderName=name)["CapacityProvider"]
        last = cp["State"]
        if last in target_states:
            return cp
        if last == "Failed":
            raise AssertionError(f"capacity provider {name} entered Failed state")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"capacity provider {name} to reach {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"capacity provider {name} never reached {target_states} (last={last}) within {timeout_s}s")


def _wait_function_version_state(ctx, cp_name: str, arn_suffix: str, target_states: set, timeout_s: float) -> dict:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        versions = lam.list_function_versions_by_capacity_provider(CapacityProviderName=cp_name)[
            "FunctionVersions"
        ]
        match = next((v for v in versions if v["FunctionArn"].endswith(arn_suffix)), None)
        if match is not None:
            last = match["State"]
            if last in target_states:
                return match
            if last == "Failed":
                raise AssertionError(f"function version {arn_suffix} entered Failed state")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"function version {arn_suffix} to reach {target_states}: the run budget ended first; not graded")
    raise AssertionError(
        f"function version {arn_suffix} never reached {target_states} (last={last}) within {timeout_s}s"
    )


def _delete_capacity_provider_when_empty(ctx, name: str, timeout_s: float = 600.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            return
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code == "ResourceNotFoundException":
                return
            if last_code != "ResourceConflictException":
                raise
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"capacity provider {name} to become deletable: the run budget ended first; not graded")
    raise AssertionError(f"capacity provider {name} never became deletable (last_code={last_code})")


# Resources in a VPC delete asynchronously and leave AWS-managed ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry DependencyViolation in the same window, and raise naming the
# ENIs still attached. Teardown-only; the window is shared by all of one check's network deletes.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
    the group must stay absent across reads spanning 5 s. Only an already-absent group is
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
        absent_since = None
        while time.monotonic() < deadline:
            time.sleep(1.0)
            if present():
                break
            absent_since = absent_since or time.monotonic()
            if time.monotonic() - absent_since >= 5.0:
                return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"log group {group} still present 30 s after delete_log_group")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
