"""delete-app-double-delete-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-app-double-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """Calling DeleteApp twice on the same App is rejected, not silently repeated."""
    sm = ctx.client("sagemaker")

    role_arn = _create_sagemaker_role(ctx)
    vpc_id, subnet_ids = _get_vpc_subnets(ctx, min_count=1)
    domain_id = _create_domain(ctx, role_arn, vpc_id, subnet_ids)
    _wait_domain_status(ctx, domain_id, "InService")

    user = ctx.unique_name("sim2real-user-")
    sm.create_user_profile(DomainId=domain_id, UserProfileName=user)
    ctx.on_cleanup(lambda: _cleanup_user_profile(ctx, domain_id, user))
    _wait_user_profile_status(ctx, domain_id, user, "InService")

    app_name = ctx.unique_name("sim2real-app-")
    sm.create_app(DomainId=domain_id, UserProfileName=user, AppType="JupyterServer", AppName=app_name)
    ctx.on_cleanup(lambda: _cleanup_app(ctx, domain_id, user, app_name))
    _wait_app_status(ctx, domain_id, user, app_name, "InService")

    # Positive control: the first delete on a healthy App succeeds normally.
    ident = dict(DomainId=domain_id, UserProfileName=user, AppType="JupyterServer", AppName=app_name)
    sm.delete_app(**ident)

    # Negative: a second delete on the same App must be rejected, not silently accepted
    # as if it were a fresh, independent deletion. A JupyterServer App can finish
    # deleting within a second, so the refusal names whichever state it is in at the
    # moment of the second call; the status read on either side of that call decides
    # which exact message is due.
    before = sm.describe_app(**ident)["Status"]
    code, message = _error_call(lambda: sm.delete_app(**ident))
    after = sm.describe_app(**ident)["Status"]
    assert before in ("Deleting", "Deleted"), f"expected Deleting or Deleted after the first delete, got {before!r}"
    assert code == "ValidationException", f"expected ValidationException on double delete, got {code!r} ({message!r})"
    deleting = f"App [{app_name}] is already being deleted. Wait until the app is deleted."
    deleted = (
        f"App [{app_name}] has already been deleted. For tracking purposes, apps are "
        "available in the ListApps API results for only 24 hours after deletion."
    )
    if before == after:
        expected = {"Deleting": deleting, "Deleted": deleted}[before]
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        # The App went Deleting -> Deleted around the call: either exact refusal is due.
        assert message in (deleting, deleted), (
            f"expected message {deleting!r} or {deleted!r}, got {message!r}"
        )

    # Effect-absence: the rejected second call did not perturb the App's lifecycle -
    # it is still on the single deletion path started by the first call.
    assert after in ("Deleting", "Deleted"), after

    _wait_app_status(ctx, domain_id, user, app_name, "Deleted", allow_not_found=True)


# ===== helpers =====

def _error_call(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_sagemaker_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role["Arn"]


def _get_vpc_subnets(ctx: Any, min_count: int = 1) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets[:min_count]]
        if len(subnet_ids) >= min_count:
            return vpc_id, subnet_ids
    vpc = ec2.create_vpc(
        CidrBlock="10.192.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(min_count):
        az = azs[i % len(azs)]["ZoneName"]
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.192.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-subnet-")}]}],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _retry(fn: Callable[[], Any], attempts: int = 12, delay: float = 15.0) -> None:
    for i in range(attempts):
        try:
            fn()
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


def _create_domain(ctx: Any, role_arn: str, vpc_id: str, subnet_ids: list[str]) -> str:
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-domain-")
    # A freshly-created role is not always immediately assumable by SageMaker; bound
    # the retry on the actual failure mode instead of sleeping a guessed duration.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            resp = sm.create_domain(
                DomainName=name,
                AuthMode="IAM",
                DefaultUserSettings={"ExecutionRole": role_arn},
                SubnetIds=subnet_ids,
                VpcId=vpc_id,
            )
            break
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
    domain_id = resp["DomainId"]
    ctx.on_cleanup(lambda: _cleanup_domain(ctx, domain_id))
    return domain_id


def _cleanup_domain(ctx: Any, domain_id: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            sm.describe_domain(DomainId=domain_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(15)


def _cleanup_app(ctx: Any, domain_id: str, user: str, app_name: str) -> None:
    sm = ctx.client("sagemaker")
    ident = dict(DomainId=domain_id, UserProfileName=user, AppType="JupyterServer", AppName=app_name)
    try:
        sm.delete_app(**ident)
    except ClientError as exc:
        # a delete already in flight (ValidationException) or an App already gone
        if exc.response["Error"]["Code"] not in ("ResourceNotFound", "ValidationException"):
            raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            if sm.describe_app(**ident)["Status"] == "Deleted":
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(10)


def _cleanup_user_profile(ctx: Any, domain_id: str, user: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_user_profile(DomainId=domain_id, UserProfileName=user)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            sm.describe_user_profile(DomainId=domain_id, UserProfileName=user)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(10)


def _wait_domain_status(ctx: Any, domain_id: str, want: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_domain(DomainId=domain_id)["Status"]
        if status == want:
            return
        if status in ("Failed", "Delete_Failed", "Update_Failed"):
            raise AssertionError(f"domain entered {status} while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"domain did not reach {want} within {timeout_s}s")


def _wait_user_profile_status(ctx: Any, domain_id: str, user: str, want: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_user_profile(DomainId=domain_id, UserProfileName=user)["Status"]
        if status == want:
            return
        if status in ("Failed", "Delete_Failed", "Update_Failed"):
            raise AssertionError(f"user profile entered {status} while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"user profile did not reach {want} within {timeout_s}s")


def _wait_app_status(
    ctx: Any,
    domain_id: str,
    user: str,
    app_name: str,
    want: str,
    timeout_s: float = 600.0,
    interval_s: float = 10.0,
    allow_not_found: bool = False,
) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = sm.describe_app(
                DomainId=domain_id, UserProfileName=user, AppType="JupyterServer", AppName=app_name
            )["Status"]
        except ClientError as exc:
            if allow_not_found and exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if status == want:
            return
        if status == "Failed":
            raise AssertionError(f"app entered Failed while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"app did not reach {want} within {timeout_s}s")


# EC2 network teardown: AWS-managed ENIs of resources deleted asynchronously in this VPC make
# DeleteSubnet / DeleteVpc fail with DependencyViolation until they leave, so wait (bounded) for
# them, retry DependencyViolation in the same window shared by all network deletes, then raise.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
