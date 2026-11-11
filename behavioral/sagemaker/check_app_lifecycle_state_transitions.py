"""app-lifecycle-state-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "app-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["sagemaker"]
_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A JupyterServer App reads Pending right after CreateApp, then reaches InService, and after
    DeleteApp reaches Deleted, rather than jumping straight to a terminal state.
    """
    sm = ctx.client("sagemaker")
    teardown: dict[str, float] = {}
    vpc_id, subnet_ids = _get_vpc_subnets(ctx, min_count=2)
    role_arn = _create_domain_execution_role(ctx)

    domain_name = ctx.unique_name("sim2real-domain-")
    created = sm.create_domain(
        DomainName=domain_name,
        AuthMode="IAM",
        DefaultUserSettings={"ExecutionRole": role_arn},
        VpcId=vpc_id,
        SubnetIds=subnet_ids,
        AppNetworkAccessType="PublicInternetOnly",
        Tags=_TAGS,
    )
    domain_id = created["DomainId"]
    ctx.on_cleanup(lambda: _delete_domain(sm, domain_id, teardown))

    domain_status = _poll_until(
        probe=lambda: sm.describe_domain(DomainId=domain_id)["Status"],
        terminal={"InService", "Failed"},
        timeout_s=1800,
        interval_s=20,
        what="Domain",
    )
    assert domain_status == "InService", f"expected Domain Status=InService, got {domain_status!r}"

    user_profile_name = ctx.unique_name("sim2real-user-")
    sm.create_user_profile(DomainId=domain_id, UserProfileName=user_profile_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_user_profile(sm, domain_id, user_profile_name, teardown))
    profile_status = _poll_until(
        probe=lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=user_profile_name)["Status"],
        terminal={"InService", "Failed"},
        timeout_s=600,
        interval_s=15,
        what="UserProfile",
    )
    assert profile_status == "InService", f"expected UserProfile Status=InService, got {profile_status!r}"

    app_name = ctx.unique_name("sim2real-app-")
    sm.create_app(
        DomainId=domain_id,
        UserProfileName=user_profile_name,
        AppType="JupyterServer",
        AppName=app_name,
        Tags=_TAGS,
    )

    # Immediately after creation the app must be in a transitional state, not already InService.
    first_desc = sm.describe_app(
        DomainId=domain_id, AppType="JupyterServer", AppName=app_name, UserProfileName=user_profile_name
    )
    assert first_desc["Status"] == "Pending", (
        f"expected App Status=Pending immediately after CreateApp, got {first_desc['Status']!r}"
    )

    app_status = _poll_until(
        probe=lambda: sm.describe_app(
            DomainId=domain_id, AppType="JupyterServer", AppName=app_name, UserProfileName=user_profile_name
        )["Status"],
        terminal={"InService", "Failed"},
        timeout_s=900,
        interval_s=15,
        what="App",
    )
    assert app_status == "InService", f"expected App Status=InService, got {app_status!r}"

    sm.delete_app(
        DomainId=domain_id, AppType="JupyterServer", AppName=app_name, UserProfileName=user_profile_name
    )

    deleted_status = _poll_until(
        probe=lambda: sm.describe_app(
            DomainId=domain_id, AppType="JupyterServer", AppName=app_name, UserProfileName=user_profile_name
        )["Status"],
        terminal={"Deleted", "Failed"},
        timeout_s=600,
        interval_s=15,
        what="App delete",
    )
    assert deleted_status == "Deleted", f"expected App Status=Deleted, got {deleted_status!r}"


def _poll_until(probe, terminal: set[str], timeout_s: float, interval_s: float, what: str):
    """Poll until `probe()` returns a value in `terminal`. Raises on timeout instead of
    returning the last (non-terminal) value -- a timeout and a genuine terminal state must
    not be indistinguishable to the caller."""
    deadline = time.monotonic() + timeout_s
    value = probe()
    while value not in terminal:
        if time.monotonic() > deadline:
            raise AssertionError(f"{what} did not reach a terminal state within {timeout_s}s (last: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _get_vpc_subnets(ctx, min_count: int) -> tuple[str, list[str]]:
    """Use the shared network if it has enough subnets, else provision a fresh VPC + subnets."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets[:min_count]]
        if len(subnet_ids) >= min_count:
            return vpc_id, subnet_ids

    vpc = ec2.create_vpc(
        CidrBlock="10.201.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(min_count):
        az = azs[i % len(azs)]["ZoneName"]
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.201.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS}],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _ignore_not_found(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not exc.response["Error"]["Code"].endswith(".NotFound"):
            raise


def _create_domain_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-domain-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=_TAGS
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    # Cleanups run in reverse order: the policy is detached before the role is deleted.
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    ctx.on_cleanup(lambda: _detach_policy(iam, role_name, policy_arn))
    return role_arn


# SageMaker teardowns share one window that leaves room for the network deletes after them.
_SM_TEARDOWN_S = 540.0


def _until_gone(teardown: dict, what: str, delete, describe) -> None:
    """Delete, retrying ResourceInUse every 2 s, then poll until describe reports ResourceNotFound."""
    deadline = teardown.setdefault("deadline", time.monotonic() + _SM_TEARDOWN_S)
    deleted = False
    while True:
        try:
            if deleted:
                describe()
            else:
                delete()
                deleted = True
                continue
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if deleted or code != "ResourceInUse":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} was not deleted within {_SM_TEARDOWN_S}s")
        time.sleep(2)


def _delete_domain(sm, domain_id: str, teardown: dict) -> None:
    _until_gone(
        teardown,
        f"domain {domain_id}",
        lambda: sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"}),
        lambda: sm.describe_domain(DomainId=domain_id),
    )


def _delete_user_profile(sm, domain_id: str, name: str, teardown: dict) -> None:
    _until_gone(
        teardown,
        f"user profile {name}",
        lambda: sm.delete_user_profile(DomainId=domain_id, UserProfileName=name),
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=name),
    )


def _detach_policy(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


# AWS-managed ENIs leave a VPC asynchronously, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can
# fail with DependencyViolation; teardown waits for the ENIs within one shared window, retries
# DependencyViolation, and raises naming the ENIs still attached.
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
