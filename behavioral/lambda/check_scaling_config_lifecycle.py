"""scaling-config-lifecycle."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "scaling-config-lifecycle"
GROUP = 'concurrency'
SERVICES = ['lambda']

ASSUME_ROLE_POLICY = json.dumps(
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


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _exec_role_arn(ctx):
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn



def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_settled(lam, fn, timeout_s=280):
    """Wait for the function to leave the transient `Pending` creation state.

    A Managed-Instances function with no FunctionScalingConfig yet has zero warm
    execution environments, so its settled terminal state is `ActiveNonInvocable`, not
    `Active`. This runs before the check ever
    applies a scaling config, so waiting for exactly `Active` here would time out on a
    perfectly healthy function.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] in ("Active", "ActiveNonInvocable"):
            return
        time.sleep(2.0)
    raise AssertionError(f"{fn} did not settle within {timeout_s}s. Last: {last!r}")


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=4.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _call_with_retry(fn, *, retryable=("InvalidParameterValueException",), timeout_s=60, interval_s=3.0):
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
    raise last_exc


def _ensure_operator_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cp-op-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=ASSUME_ROLE_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator",
        )
    except ClientError:
        pass
    return arn


def _ensure_cp_network(ctx, *, cidr="10.79.0.0/16", subnet_cidr="10.79.1.0/24"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr)["Subnet"]["SubnetId"]
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-cp-sg-"),
        Description="sim2real-behav capacity provider sg",
        VpcId=vpc_id,
    )["GroupId"]

    def _cleanup():
        # DependencyViolation is retried while the capacity provider's ENIs are released.
        deadline = time.monotonic() + 120
        for f, not_found in (
            (lambda: ec2.delete_security_group(GroupId=sg_id), "InvalidGroup.NotFound"),
            (lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"),
            (lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"),
        ):
            while True:
                try:
                    f()
                    break
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code == not_found:
                        break
                    if code != "DependencyViolation" or time.monotonic() >= deadline:
                        raise
                    time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return subnet_id, sg_id


def _delete_capacity_provider(ctx, lam, name):
    # Two independent budgets, not one shared deadline: the delete *request* can be
    # rejected with ResourceConflictException while the provider is still settling, and
    # the underlying EC2 Managed Instances teardown after a successful delete request can
    # outlast a combined budget, which starves the
    # disappearance-confirmation loop of the time it needs and leaks the VPC/SG this check
    # created underneath the capacity provider.
    request_deadline = time.monotonic() + 120
    while True:
        try:
            lam.delete_capacity_provider(CapacityProviderName=name)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceConflictException" or time.monotonic() >= request_deadline:
                raise
            time.sleep(2)
    gone_deadline = time.monotonic() + 600
    while time.monotonic() < gone_deadline:
        try:
            lam.get_capacity_provider(CapacityProviderName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(2)
    raise AssertionError(f"capacity provider {name} still present 600s after its delete")


def _create_capacity_provider(ctx, lam, name):
    subnet_id, sg_id = _ensure_cp_network(ctx)
    operator_role_arn = _ensure_operator_role(ctx)
    params = dict(
        CapacityProviderName=name,
        VpcConfig={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
        PermissionsConfig={"CapacityProviderOperatorRoleArn": operator_role_arn},
        InstanceRequirements={"Architectures": ["x86_64"]},
    )
    resp = _call_with_retry(lambda: lam.create_capacity_provider(**params))
    ctx.on_cleanup(lambda: _delete_capacity_provider(ctx, lam, name))
    return resp


def _create_managed_instance_function(ctx, lam, name, cp_arn):
    params = dict(
        FunctionName=name,
        Runtime="python3.13",
        Role=_exec_role_arn(ctx),
        Handler="index.handler",
        Code={"ZipFile": _make_zip("def handler(e, c): return e")},
        Timeout=10,
        MemorySize=2048,
        Architectures=["x86_64"],
        CapacityProviderConfig={
            "LambdaManagedInstancesCapacityProviderConfig": {"CapacityProviderArn": cp_arn}
        },
    )
    resp = _call_with_retry(lambda: lam.create_function(**params))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    return resp


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Scaling config changes persist, are actually applied, and are reflected in capacity
    provider version listings."""
    lam = ctx.client("lambda")
    cp_name = ctx.unique_name("sim2real-behav-cp-")
    try:
        created = _create_capacity_provider(ctx, lam, cp_name)
        cp_arn = created["CapacityProvider"]["CapacityProviderArn"]
        active = _poll_until(
            lambda: lam.get_capacity_provider(CapacityProviderName=cp_name),
            lambda r: r["CapacityProvider"]["State"] in ("Active", "Failed"),
            timeout_s=180,
            interval_s=4.0,
            description=f"capacity provider {cp_name} reach terminal state",
        )
        assert active["CapacityProvider"]["State"] == "Active", active

        fn = ctx.unique_name("sim2real-behav-cpfn-")
        _create_managed_instance_function(ctx, lam, fn, cp_arn)
        _wait_settled(lam, fn, timeout_s=280)

        v1 = lam.publish_version(FunctionName=fn)["Version"]

        # Real AWS rejects MinExecutionEnvironments=0 unless MaxExecutionEnvironments is
        # also 0 (InvalidParameterValueException) -- both are pinned
        # to 1 so the request is valid while still being a nontrivial scaling config.
        # PutFunctionScalingConfig also answers ResourceConflictException
        # while the function is still settling into its capacity-provider-backed state, which
        # is genuine asynchrony (the operation's own error list documents it) -- bounded retry,
        # not a hard rejection.
        put = _call_with_retry(
            lambda: lam.put_function_scaling_config(
                FunctionName=fn,
                Qualifier=v1,
                FunctionScalingConfig={"MinExecutionEnvironments": 1, "MaxExecutionEnvironments": 1},
            ),
            retryable=("InvalidParameterValueException", "ResourceConflictException"),
            timeout_s=120,
        )
        assert put["FunctionState"] in (
            "Pending", "Active", "Deactivated", "ActiveNonInvocable", "Failed",
        ), put

        got = _poll_until(
            lambda: lam.get_function_scaling_config(FunctionName=fn, Qualifier=v1),
            lambda r: r.get("RequestedFunctionScalingConfig") is not None,
            timeout_s=120,
            interval_s=5.0,
            description="scaling config visible via GetFunctionScalingConfig",
        )
        assert got["RequestedFunctionScalingConfig"]["MaxExecutionEnvironments"] == 1, got

        applied = _poll_until(
            lambda: lam.get_function_scaling_config(FunctionName=fn, Qualifier=v1),
            lambda r: (r.get("AppliedFunctionScalingConfig") or {}).get("MaxExecutionEnvironments") == 1,
            timeout_s=180,
            interval_s=5.0,
            description="requested scaling config actually applied (AppliedFunctionScalingConfig)",
        )
        assert applied["AppliedFunctionScalingConfig"]["MinExecutionEnvironments"] == 1, applied

        # A published version does not appear in this list until its own Managed-Instances
        # execution environment independently reaches a terminal state -- confirmed real
        # asynchrony, not a flake -- so this is a bounded poll, not a single read.
        _poll_until(
            lambda: lam.list_function_versions_by_capacity_provider(
                CapacityProviderName=cp_name
            )["FunctionVersions"],
            lambda vs: any(v.get("FunctionArn", "").endswith(f":{fn}:{v1}") for v in vs),
            timeout_s=900,
            interval_s=15.0,
            description=f"version {fn}:{v1} to appear in ListFunctionVersionsByCapacityProvider",
        )
    except ClientError as exc:
        raise AssertionError(
            f"Lambda Managed Instances scaling-config flow not usable in this account/region: {exc}"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
