"""create-app-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-app-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApp reaches InService, DeleteApp transitions it to Deleted, and the app record
    is retained (not purged) for the 24h metadata-retention window documented by SageMaker --
    so an immediate DescribeApp reports Status=Deleted rather than ResourceNotFound."""
    sm = ctx.client("sagemaker")
    role_arn = _ensure_execution_role(ctx)
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)

    domain_name = ctx.unique_name("sim2real-behav-dom-")
    create_resp = sm.create_domain(
        DomainName=domain_name,
        AuthMode="IAM",
        DefaultUserSettings={"ExecutionRole": role_arn},
        VpcId=vpc_id,
        SubnetIds=subnet_ids,
        AppNetworkAccessType="PublicInternetOnly",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    domain_id = create_resp["DomainId"]
    ctx.on_cleanup(lambda: _delete_domain_and_wait(ctx, sm, domain_id))
    _wait_domain_status(ctx, domain_id, {"InService", "Failed"}, timeout_s=900)
    domain_status = sm.describe_domain(DomainId=domain_id)["Status"]
    assert domain_status == "InService", f"domain never reached InService, ended at {domain_status}"

    user_profile = ctx.unique_name("sim2real-behav-up-")
    sm.create_user_profile(
        DomainId=domain_id,
        UserProfileName=user_profile,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user_profile_and_wait(sm, domain_id, user_profile))
    _wait_user_profile_status(ctx, domain_id, user_profile, {"InService", "Failed"}, timeout_s=300)
    up_status = sm.describe_user_profile(DomainId=domain_id, UserProfileName=user_profile)["Status"]
    assert up_status == "InService", f"user profile never reached InService, ended at {up_status}"

    app_name = ctx.unique_name("sim2real-behav-app-")
    sm.create_app(
        DomainId=domain_id,
        UserProfileName=user_profile,
        AppType="JupyterServer",
        AppName=app_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_app_and_wait(sm, domain_id, user_profile, app_name))

    status = _wait_app_status(ctx, domain_id, user_profile, app_name, {"InService", "Failed"}, timeout_s=600)
    assert status == "InService", f"app never reached InService, ended at {status}"

    sm.delete_app(DomainId=domain_id, UserProfileName=user_profile, AppType="JupyterServer", AppName=app_name)
    final_status = _wait_app_status(ctx, domain_id, user_profile, app_name, {"Deleted", "Failed"}, timeout_s=300)
    assert final_status == "Deleted", f"app never reached Deleted, ended at {final_status}"

    # Per AWS docs: app metadata is retained for ~24h after shutdown, so DescribeApp keeps
    # succeeding with the terminal Deleted status rather than raising ResourceNotFound.
    describe_after_delete = sm.describe_app(
        DomainId=domain_id, UserProfileName=user_profile, AppType="JupyterServer", AppName=app_name
    )
    assert describe_after_delete["Status"] == "Deleted", (
        f"expected the app record to persist with Status=Deleted, got {describe_after_delete['Status']!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _ensure_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)

    # Bounded wait for the new role/attachment to become visible before SageMaker's
    # CreateDomain tries to assume it -- IAM writes are eventually consistent.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            if any(p["PolicyArn"] == policy_arn for p in attached):
                break
        except Exception:
            pass
        time.sleep(2)
    else:
        raise AssertionError(f"role {role_name} policy attachment never became visible within 30s")
    return role_arn


def _default_vpc_subnets(ctx):
    """Up to two subnets of the run's network VPC; a VPC with its own subnets when it has none."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    if subnet_ids:
        return vpc_id, subnet_ids

    vpc_id = ec2.create_vpc(
        CidrBlock="10.193.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")},
                    {"Key": "sim2real-check", "Value": CHECK},
                ],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    azs = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.193.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")},
                        {"Key": "sim2real-check", "Value": CHECK},
                    ],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _retry(fn, attempts=12, delay=15.0):
    from botocore.exceptions import ClientError

    for i in range(attempts):
        try:
            fn()
            return
        except ClientError:
            if i == attempts - 1:
                raise
            time.sleep(delay)


_POLL_INTERVAL_S = 2.0
_TEARDOWN_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_status(ctx, describe, terminal_statuses, timeout_s, what):
    """Poll describe() every 2 s until it returns a terminal status, bounded by the time left."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = describe()
        if status in terminal_statuses:
            return status
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what} to reach {terminal_statuses}: the run budget ended first; not graded")
            raise AssertionError(f"{what} did not reach {terminal_statuses} within {timeout_s:.0f}s (last={status})")
        time.sleep(_POLL_INTERVAL_S)


def _wait_domain_status(ctx, domain_id, terminal_statuses, timeout_s):
    sm = ctx.client("sagemaker")
    return _poll_status(
        ctx, lambda: sm.describe_domain(DomainId=domain_id)["Status"], terminal_statuses, timeout_s,
        f"domain {domain_id}",
    )


def _wait_user_profile_status(ctx, domain_id, user_profile, terminal_statuses, timeout_s):
    sm = ctx.client("sagemaker")
    return _poll_status(
        ctx,
        lambda: sm.describe_user_profile(DomainId=domain_id, UserProfileName=user_profile)["Status"],
        terminal_statuses, timeout_s, "user profile",
    )


def _wait_app_status(ctx, domain_id, user_profile, app_name, terminal_statuses, timeout_s):
    sm = ctx.client("sagemaker")
    return _poll_status(
        ctx,
        lambda: sm.describe_app(
            DomainId=domain_id, UserProfileName=user_profile, AppType="JupyterServer", AppName=app_name
        )["Status"],
        terminal_statuses, timeout_s, "app",
    )


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
        _time.sleep(_TEARDOWN_POLL_S)
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
        _time.sleep(_TEARDOWN_POLL_S)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _delete_app_and_wait(sm, domain_id, user_profile, app_name, timeout_s=600.0):
    """Delete the app unless the check already did, and wait for Deleted so the profile can go."""
    from botocore.exceptions import ClientError

    ident = {"DomainId": domain_id, "UserProfileName": user_profile, "AppType": "JupyterServer", "AppName": app_name}
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = sm.describe_app(**ident)["Status"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if status in ("Deleted", "Failed"):
            return
        if status != "Deleting":
            sm.delete_app(**ident)
        if time.monotonic() >= deadline:
            raise AssertionError(f"app {app_name} still {status} {timeout_s:.0f}s into teardown")
        time.sleep(_TEARDOWN_POLL_S)


def _delete_user_profile_and_wait(sm, domain_id, user_profile, timeout_s=600.0):
    """Delete the user profile and wait until it is gone, so the domain can be deleted."""
    from botocore.exceptions import ClientError

    try:
        sm.delete_user_profile(DomainId=domain_id, UserProfileName=user_profile)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFound":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.describe_user_profile(DomainId=domain_id, UserProfileName=user_profile)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(_TEARDOWN_POLL_S)
    raise AssertionError(f"user profile {user_profile} still exists {timeout_s:.0f}s after DeleteUserProfile")


def _delete_domain_and_wait(ctx, sm, domain_id, timeout_s=1200.0):
    """Delete the domain, wait until it is gone, then delete the NFS security groups it left."""
    from botocore.exceptions import ClientError

    try:
        sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_domain(DomainId=domain_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFound":
                break
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"domain {domain_id} still exists {timeout_s:.0f}s after DeleteDomain")
        time.sleep(_TEARDOWN_POLL_S)
    ec2 = ctx.client("ec2")
    names = [f"security-group-for-inbound-nfs-{domain_id}", f"security-group-for-outbound-nfs-{domain_id}"]
    groups = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": names}])["SecurityGroups"]
    for g in groups:
        if g["IpPermissions"]:
            ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
        if g["IpPermissionsEgress"]:
            ec2.revoke_security_group_egress(GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
    for g in groups:
        while True:
            try:
                ec2.delete_security_group(GroupId=g["GroupId"])
                break
            except ClientError as e:
                if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(_TEARDOWN_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
