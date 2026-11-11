"""delete-capacity-provider-in-use-conflict."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError, ParamValidationError

from behavioral_harness import tags

CHECK = "delete-capacity-provider-in-use-conflict"
GROUP = "error-semantics"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCapacityProvider on a provider still referenced by a function is rejected with
    ResourceConflictException and leaves it intact; after the function is deleted it succeeds.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_DeleteCapacityProvider.html
    """
    lam = ctx.client("lambda")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    if not hasattr(lam, "create_capacity_provider"):
        raise AssertionError(
            "unreachable: this boto3/botocore build has no create_capacity_provider operation "
            "for the lambda client (CapacityProvider preview API not present)"
        )

    subnet_ids, sg_id = _find_default_vpc_network(ec2, ctx=ctx)
    if not subnet_ids or sg_id is None:
        raise AssertionError(
            "unreachable: no default VPC with subnets/security-group available to build the "
            "CapacityProvider VpcConfig in this account/region"
        )

    role_arn = _create_capacity_provider_role(ctx, iam)
    cp_name = ctx.unique_name("sim2real-behav-cp-")

    # A role whose policy attachment just landed can take a few seconds to become
    # visible to CreateCapacityProvider's own validation; retry on that specific,
    # transient condition rather than a bare sleep.
    created = None
    create_s = _budget_s(ctx, 60.0)
    create_deadline = time.monotonic() + create_s
    last_create_err = None
    while time.monotonic() < create_deadline:
        try:
            created = lam.create_capacity_provider(
                CapacityProviderName=cp_name,
                VpcConfig={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
                PermissionsConfig={"CapacityProviderOperatorRoleArn": role_arn},
                InstanceRequirements={"Architectures": ["x86_64"]},
                CapacityProviderScalingConfig={
                    "MaxVCpuCount": 16,
                    "ScalingMode": "Auto",
                },
                Tags={"sim2real:managed": "true"},
            )
            break
        except ClientError as e:
            last_create_err = e
            msg = e.response["Error"].get("Message", "")
            if (
                e.response["Error"]["Code"] == "InvalidParameterValueException"
                and "operator role" in msg
            ):
                time.sleep(1)
                continue
            raise AssertionError(
                "unreachable: CreateCapacityProvider was rejected in this account/region "
                f"({e.response['Error']['Code']}: {msg})"
            )
    if created is None:
        if _budget_spent(ctx):
            raise TimeoutError("CreateCapacityProvider to accept the operator role: the run budget ended first; not graded")
        raise AssertionError(
            "unreachable: CreateCapacityProvider kept rejecting the operator role as "
            f"invalid/insufficient after {create_s:.0f}s of IAM-propagation retries ({last_create_err})"
        )

    cp_arn = created["CapacityProvider"]["CapacityProviderArn"]
    ctx.on_cleanup(lambda: _delete_capacity_provider_when_possible(lam, cp_name))

    state = None
    try:
        state = _poll_until(
            lambda: lam.get_capacity_provider(CapacityProviderName=cp_name)[
                "CapacityProvider"
            ]["State"],
            lambda s: s in ("Active", "Failed"),
            timeout_s=_budget_s(ctx, 180.0),
            interval_s=1,
            ctx=ctx,
        )
    except AssertionError:
        raise AssertionError(
            "unreachable: capacity provider did not settle to Active/Failed in time in this "
            "environment"
        )
    if state != "Active":
        raise AssertionError(
            f"unreachable: capacity provider settled to {state!r} instead of Active"
        )

    # A "Lambda Default" function cannot be converted to a Managed-Instances function
    # after the fact -- CapacityProviderConfig must be supplied at CreateFunction time,
    # not layered on afterward with UpdateFunctionConfiguration.
    try:
        fn = _create_function(
            ctx,
            Runtime="python3.13",
            MemorySize=2048,
            EphemeralStorage={"Size": 512},
            Architectures=["x86_64"],
            Publish=True,
            CapacityProviderConfig={
                "LambdaManagedInstancesCapacityProviderConfig": {
                    "CapacityProviderArn": cp_arn
                }
            },
        )
    except (ClientError, ParamValidationError) as e:
        raise AssertionError(
            f"unreachable: creating a function attached to a CapacityProvider is not usable "
            f"in this environment ({e})"
        )

    # Declaring zero desired execution environments means nothing ever provisions --
    # request at least one so the version actually settles instead of sitting in
    # Pending forever waiting for demand that will never arrive in this check. The
    # version can still be mid-provisioning right after Publish, which the API
    # surfaces as a transient ResourceConflictException; retry that specific,
    # bounded condition rather than sleeping blindly.
    scaling_s = _budget_s(ctx, 120.0)
    scaling_deadline = time.monotonic() + scaling_s
    last_scaling_err = None
    while time.monotonic() < scaling_deadline:
        try:
            lam.put_function_scaling_config(
                FunctionName=fn["name"],
                Qualifier="1",
                FunctionScalingConfig={
                    "MinExecutionEnvironments": 1,
                    "MaxExecutionEnvironments": 2,
                },
            )
            last_scaling_err = None
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceConflictException":
                raise
            last_scaling_err = e
            time.sleep(1)
    if last_scaling_err is not None:
        if _budget_spent(ctx):
            raise TimeoutError("PutFunctionScalingConfig to stop reporting a transient conflict: the run budget ended first; not graded")
        raise AssertionError(
            "unreachable: PutFunctionScalingConfig kept reporting a transient conflict for "
            f"{scaling_s:.0f}s ({last_scaling_err})"
        )
    fn_version_state = _poll_until(
        lambda: _function_version_state(lam, cp_name, fn["name"], "1"),
        lambda s: s in ("Active", "Failed"),
        timeout_s=_budget_s(ctx, 800.0),
        interval_s=1.0,
        ctx=ctx,
    )
    if fn_version_state != "Active":
        raise AssertionError(
            f"unreachable: function version settled to {fn_version_state!r} instead of "
            "Active under this capacity provider"
        )

    # Break exactly one thing: try to delete the provider while a function still
    # references it via CapacityProviderConfig.
    try:
        lam.delete_capacity_provider(CapacityProviderName=cp_name)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"].get("Message")
    else:
        raise AssertionError("expected DeleteCapacityProvider to be refused while in use, but it succeeded")

    assert error_code == "ResourceConflictException", (
        f"expected ResourceConflictException, got {error_code!r}"
    )
    fn_version_arn = f"{fn['arn'].rsplit(':function:', 1)[0]}:function:{fn['name']}:1"
    expected_conflict_msg = (
        "The capacity provider is currently in use by 1 function. To delete this capacity "
        f"provider, first remove its association with {fn_version_arn}."
    )
    assert error_msg == expected_conflict_msg, (
        f"expected message {expected_conflict_msg!r}, got {error_msg!r}"
    )

    # Effect-absent: an independent read shows the provider was never touched by the
    # rejected call -- still there, not transitioning to Deleting, and still listed as
    # governing the attached function version.
    still_there = lam.get_capacity_provider(CapacityProviderName=cp_name)[
        "CapacityProvider"
    ]
    assert still_there["State"] != "Deleting", (
        f"provider entered Deleting despite the rejected delete: {still_there['State']!r}"
    )
    versions = lam.list_function_versions_by_capacity_provider(
        CapacityProviderName=cp_name
    )["FunctionVersions"]
    assert any(v["FunctionArn"].endswith(f":{fn['name']}:1") for v in versions), (
        f"attached function version no longer listed under the provider after the rejected "
        f"delete: {versions!r}"
    )

    # The teardown registered by _create_function tolerates the function already being gone.
    lam.delete_function(FunctionName=fn["name"])

    # Positive control: the identical DeleteCapacityProvider call now succeeds once the
    # dependency is gone -- proving the earlier rejection was about the attachment, not
    # about the API (or this account/region) being broken.
    _delete_capacity_provider_when_possible(lam, cp_name)

    # And the delete is real: DeleteCapacityProvider is asynchronous (HTTP 202 --
    # the provider moves to Deleting and disappears in the background), so bound the
    # wait for the independent read to return the specific not-found code rather than
    # checking exactly once.
    final_s = _budget_s(ctx, 300.0)
    final_deadline = time.monotonic() + final_s
    final_code = "Found"
    final_msg = None
    while time.monotonic() < final_deadline:
        try:
            still = lam.get_capacity_provider(CapacityProviderName=cp_name)[
                "CapacityProvider"
            ]
            final_code = None
            if still["State"] not in ("Deleting", "Active"):
                raise AssertionError(
                    f"provider left Deleting for an unexpected state: {still['State']!r}"
                )
        except ClientError as e:
            final_code = e.response["Error"]["Code"]
            final_msg = e.response["Error"].get("Message")
            break
        time.sleep(1)
    if final_code in ("Found", None) and _budget_spent(ctx):
        raise TimeoutError("the deleted capacity provider to disappear: the run budget ended first; not graded")
    assert final_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {final_code!r} "
        f"(provider did not finish deleting within {final_s:.0f}s)"
    )
    expected_missing_msg = (
        f"Capacity provider not found: {cp_arn}. Check that the ARN is correct and the "
        "capacity provider exists in this Region."
    )
    assert final_msg == expected_missing_msg, (
        f"expected message {expected_missing_msg!r}, got {final_msg!r}"
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


def _find_default_vpc_network(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        return [], None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"] if sgs else None
    return subnet_ids, sg_id


_CP_OPERATOR_POLICY_ARN = "arn:aws:iam::aws:policy/AWSLambdaManagedEC2ResourceOperator"


def _create_capacity_provider_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-behav-cprole-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn=_CP_OPERATOR_POLICY_ARN
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
    # The operator role must actually be able to manage the capacity provider's
    # underlying EC2 resources, or the provider never leaves Pending/Failed and this
    # check would misreport a real bug here as an "unreachable" environment limit.
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CP_OPERATOR_POLICY_ARN)
    return role_arn


def _delete_capacity_provider_when_possible(lam, cp_name):
    for _ in range(30):
        try:
            lam.delete_capacity_provider(CapacityProviderName=cp_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ResourceConflictException", "ResourceInUseException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise


def _function_version_state(lam, cp_name, fn_name, qualifier):
    versions = lam.list_function_versions_by_capacity_provider(
        CapacityProviderName=cp_name
    )["FunctionVersions"]
    suffix = f":{fn_name}:{qualifier}"
    match = next((v for v in versions if v["FunctionArn"].endswith(suffix)), None)
    return match["State"] if match is not None else "Pending"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"capacity provider condition (last value: {last!r}): the run budget ended first; not graded")
    raise AssertionError(
        f"condition not met within {timeout_s}s (last value: {last!r})"
    )


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def handler(event, context):\n    return {'ok': True}\n",
        )
    return buf.getvalue()


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _wait_active(lam, name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg.get("State")
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(
                f"function entered Failed state: {cfg.get('StateReason')}"
            )
        time.sleep(1)
    raise AssertionError(f"function did not become Active within {timeout_s}s")


def _create_function(ctx, **overrides):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    role_arn = _create_lambda_role(ctx)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _minimal_zip_bytes()},
        Timeout=10,
        Tags={"sim2real:managed": "true"},
    )
    # A function attached to a Managed-Instances CapacityProvider provisions real EC2
    # capacity before it goes Active, which takes much longer than a plain function.
    activation_timeout_s = 600.0 if "CapacityProviderConfig" in overrides else 120.0
    kwargs.update(overrides)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(**kwargs)
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"][
                "Code"
            ] == "InvalidParameterValueException" and "cannot be assumed" in str(e):
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise last_err

    def _cleanup_fn():
        try:
            lam.delete_function(FunctionName=name)
        except ClientError as e:
            # The check may already have deleted this function itself (to prove the
            # capacity provider becomes deletable once unreferenced); a repeat delete
            # is a no-op, not a defect.
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(lambda: _delete_function_log_group(ctx, name))
    ctx.on_cleanup(_cleanup_fn)
    if "CapacityProviderConfig" not in overrides:
        _wait_active(lam, name, timeout_s=activation_timeout_s)
    # A Managed-Instances function's readiness is tracked per-version via
    # ListFunctionVersionsByCapacityProvider, not via GetFunctionConfiguration's own
    # State -- the caller polls that once it has requested nonzero capacity.
    return {"name": name, "arn": resp["FunctionArn"], "role_arn": role_arn}


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
