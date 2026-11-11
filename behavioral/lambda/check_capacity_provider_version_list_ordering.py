"""capacity-provider-version-list-ordering."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "capacity-provider-version-list-ordering"
GROUP = "lifecycle"
SERVICES = ["lambda"]

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


_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLES: dict = {}


def _role_arn(ctx):
    """Create this check's own Lambda execution role once per run and register its cleanup."""
    import json as _json

    held = _ROLES.get(id(ctx))
    if held is not None and held[0] is ctx:
        return held[1]
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_BASIC_EXEC_POLICY))
    _ROLES[id(ctx)] = (ctx, arn)
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retrying only while a freshly created role is not yet assumable."""
    from botocore.exceptions import ClientError as _ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except _ClientError as exc:
            err = exc.response.get("Error", {})
            propagating = err.get("Code") == "InvalidParameterValueException" and "cannot be assumed" in err.get("Message", "")
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(3)


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

    A Managed-Instances function with no FunctionScalingConfig settles in `ActiveNonInvocable`
    (zero warm environments), not `Active`; only `Failed` is an error.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(
                f"Function {fn} entered Failed: {last.get('StateReason')}"
            )
        if last["State"] in ("Active", "ActiveNonInvocable"):
            return
        time.sleep(2.0)
    raise AssertionError(f"{fn} did not settle within {timeout_s}s. Last: {last!r}")


def _wait_update_settled(lam, fn, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last.get("LastUpdateStatus") in ("Successful", "Failed", None):
            return last
        time.sleep(2.0)
    raise AssertionError(f"{fn} update not settled within {timeout_s}s. Last: {last!r}")


def _poll_until(
    probe, predicate, *, timeout_s=180, interval_s=4.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _call_with_retry(
    fn, *, retryable=("InvalidParameterValueException",), timeout_s=60, interval_s=3.0
):
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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
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


def _ensure_cp_network(ctx, *, cidr="10.80.0.0/16", subnet_cidr="10.80.1.0/24"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr)["Subnet"][
        "SubnetId"
    ]
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-cp-sg-"),
        Description="sim2real-behav capacity provider sg",
        VpcId=vpc_id,
    )["GroupId"]

    def _cleanup():
        # ENIs of the deleted capacity provider can hold the network for a while: retry
        # DependencyViolation every 2 s within one 150 s window, return on not-found, raise the rest.
        deadline = time.monotonic() + 150
        for f, gone in (
            (lambda: ec2.delete_security_group(GroupId=sg_id), "InvalidGroup.NotFound"),
            (lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"),
            (lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"),
        ):
            while True:
                try:
                    f()
                    break
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code")
                    if code == gone:
                        break
                    if code != "DependencyViolation" or time.monotonic() >= deadline:
                        raise
                time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return subnet_id, sg_id


def _delete_capacity_provider(ctx, lam, name):
    # Two independent budgets: the delete request can hit ResourceConflictException while the
    # provider settles, and the EC2 Managed Instances teardown afterwards can outlast 180s on its
    # own; a shared deadline would leave the VPC this check created behind.
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
    raise AssertionError(f"capacity provider {name} was still present 600s after its delete")


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
        Role=_role_arn(ctx),
        Handler="index.handler",
        Code={"ZipFile": _make_zip("def handler(e, c): return e")},
        Timeout=10,
        MemorySize=2048,
        Architectures=["x86_64"],
        CapacityProviderConfig={
            "LambdaManagedInstancesCapacityProviderConfig": {
                "CapacityProviderArn": cp_arn
            }
        },
    )
    resp = _call_with_retry(lambda: _create_function(lam, **params))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    return resp


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFunctionVersionsByCapacityProvider orders versions by when each became visible (not by
    version number), and that order is stable across repeated reads. Raises, never skips, when
    Lambda Managed Instances is unusable in the account/region.
    """
    lam = ctx.client("lambda")
    cp_name = ctx.unique_name("sim2real-behav-cp-")
    try:
        cp = _create_capacity_provider(ctx, lam, cp_name)
    except ClientError as exc:
        raise AssertionError(
            f"Lambda Managed Instances (CreateCapacityProvider) not usable here: {exc}"
        ) from exc
    cp_arn = cp["CapacityProvider"]["CapacityProviderArn"]
    _poll_until(
        lambda: lam.get_capacity_provider(CapacityProviderName=cp_name),
        lambda r: r["CapacityProvider"]["State"] in ("Active", "Failed"),
        timeout_s=180,
        interval_s=4.0,
        description=f"capacity provider {cp_name} reach terminal state",
    )

    fn = ctx.unique_name("sim2real-behav-cpfn-")
    try:
        _create_managed_instance_function(ctx, lam, fn, cp_arn)
    except ClientError as exc:
        raise AssertionError(
            f"Lambda Managed Instances function attachment not usable in this account/region: {exc}"
        ) from exc
    _wait_settled(lam, fn, timeout_s=180)

    published = []
    for i in range(3):
        lam.update_function_code(
            FunctionName=fn, ZipFile=_make_zip(f"def handler(e, c): return {i}\n")
        )
        _wait_update_settled(lam, fn)
        pv = lam.publish_version(FunctionName=fn)
        published.append(pv["Version"])

    def _version_num(arn):
        # every published version here is a plain integer string; $LATEST (if ever
        # returned) has no numeric ordering and is excluded before this is called.
        return int(arn.rsplit(":", 1)[-1])

    # AWS does not list versions ascending by number (1, 2, 3 published in order can list as
    # [3, 1, 2]): a version appears only once its own execution environment reaches Active, so
    # order tracks readiness. The poll records the batch in which each version first appeared;
    # a version from an earlier batch must never be listed after one from a later batch, while
    # versions in the same batch are unordered relative to each other.
    discovery_batch: dict[int, int] = {}
    iteration = {"n": 0}

    def _list_versions():
        return lam.list_function_versions_by_capacity_provider(
            CapacityProviderName=cp_name
        )

    def _all_published_present(resp):
        arns = [v["FunctionArn"] for v in resp["FunctionVersions"]]
        assert "$LATEST" not in arns, (
            f"expected only numbered versions from ListFunctionVersionsByCapacityProvider, "
            f"got $LATEST in {arns}"
        )
        for v in {_version_num(a) for a in arns}:
            discovery_batch.setdefault(v, iteration["n"])
        iteration["n"] += 1
        return all(any(a.endswith(f":{v}") for a in arns) for v in published)

    first = _poll_until(
        _list_versions,
        _all_published_present,
        timeout_s=900,
        interval_s=15.0,
        description=(
            f"published versions {published} to appear in "
            "ListFunctionVersionsByCapacityProvider"
        ),
    )
    second = lam.list_function_versions_by_capacity_provider(
        CapacityProviderName=cp_name
    )

    first_arns = [v["FunctionArn"] for v in first["FunctionVersions"]]
    second_arns = [v["FunctionArn"] for v in second["FunctionVersions"]]

    assert first["CapacityProviderArn"] == cp_arn, first

    numeric_versions = [_version_num(a) for a in first_arns]
    batches = [discovery_batch[v] for v in numeric_versions]
    assert batches == sorted(batches), (
        f"expected ListFunctionVersionsByCapacityProvider order to respect the order in "
        f"which this check itself observed each version first become visible "
        f"(measured discovery batches {discovery_batch}), got versions {numeric_versions} "
        f"with batches {batches}"
    )

    assert first_arns == second_arns, (
        f"expected ListFunctionVersionsByCapacityProvider order to be stable across calls, "
        f"got {first_arns} then {second_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
