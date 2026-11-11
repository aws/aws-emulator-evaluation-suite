"""rds-proxy-lambda-custom-auth-missing-invoke-permission-negative."""

from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-proxy-lambda-custom-auth-missing-invoke-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBProxy rejects subnets split across two VPCs with InvalidParameterCombination and
    creates no proxy, while the same role and secret with a single-VPC subnet set yield an
    available proxy (RDS Proxy has no Lambda-invoked auth scheme to deny)."""
    rds = ctx.client("rds")
    good_subnet_ids, sg_id = _default_vpc_network(ctx)
    other_vpc_subnet_id = _create_throwaway_vpc_subnet(ctx)

    secret_arn = _create_secret(ctx, "admin", f"S1m2Real{uuid.uuid4().hex[:12]}")
    role_arn, _role_name = _create_proxy_role(ctx, secret_arn)

    # --- negative: subnets span two different VPCs, which RDS Proxy cannot bind to.
    # CreateDBProxy validates this synchronously and rejects with InvalidParameterCombination
    # ("Subnets must belong to only one VPC..."), not the InvalidParameterValueException docs
    # list InvalidSubnet under -- assert on the real observed error instead. ---
    mismatched_subnets = [good_subnet_ids[0], other_vpc_subnet_id]
    broken_proxy_name = ctx.unique_name("sim2real-rdsproxy-bad-")
    code, message = _error_code(
        lambda: rds.create_db_proxy(
            DBProxyName=broken_proxy_name,
            EngineFamily="MYSQL",
            Auth=[
                {
                    "AuthScheme": "SECRETS",
                    "SecretArn": secret_arn,
                    "IAMAuth": "DISABLED",
                }
            ],
            RoleArn=role_arn,
            VpcSubnetIds=mismatched_subnets,
            VpcSecurityGroupIds=[sg_id],
            RequireTLS=False,
        )
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for cross-VPC subnets, got {code!r} ({message!r})"
    )
    # message varies: RDS lists the two VPC ids in no stable order from one request to the next
    # ("Subnets must belong to only one VPC but found multiple VPCs: [<vpc>, <vpc>]"), so the
    # stable prefix and both VPC ids are graded.
    vpc_ids = {
        s["VpcId"]
        for s in ctx.client("ec2").describe_subnets(SubnetIds=mismatched_subnets)["Subnets"]
    }
    assert len(vpc_ids) == 2, f"expected the two subnets to sit in two VPCs, got {vpc_ids}"
    assert (message or "").startswith(
        "Subnets must belong to only one VPC but found multiple VPCs: "
    ), f"expected the VPC-mismatch reason in the error message, got {message!r}"
    for vpc_id in vpc_ids:
        assert vpc_id in message, f"expected {vpc_id} named in the error message, got {message!r}"

    # effect absent: CreateDBProxy failed synchronously, so no proxy object was created
    not_found_code, not_found_message = _error_code(
        lambda: rds.describe_db_proxies(DBProxyName=broken_proxy_name)
    )
    assert not_found_code == "DBProxyNotFoundFault", (
        f"expected no proxy to exist after the rejected create, got error {not_found_code!r}"
    )
    assert not_found_message == _proxy_not_found(broken_proxy_name), not_found_message

    # --- positive control: a fresh proxy, same role/secret, only the subnet set fixed to a
    # valid single-VPC set ---
    good_proxy_name = _create_proxy(ctx, secret_arn, role_arn, good_subnet_ids, sg_id)
    status = _poll_proxy_terminal_status(ctx, good_proxy_name, timeout_s=900)
    assert status == "available", (
        f"expected the proxy to reach Status=available with a valid single-VPC subnet set, got {status!r}"
    )

    # --- teardown of the positive control, proven rather than assumed: gone means unusable too ---
    rds.delete_db_proxy(DBProxyName=good_proxy_name)
    deadline = time.monotonic() + 300
    while not _proxy_gone(rds, good_proxy_name):
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected {good_proxy_name!r} to be gone within 300s of delete_db_proxy")
        time.sleep(2)
    gone_code, gone_message = _error_code(
        lambda: rds.describe_db_proxies(DBProxyName=good_proxy_name)
    )
    assert gone_code == "DBProxyNotFoundFault", (
        f"expected {good_proxy_name!r} to be gone after delete_db_proxy, got describe error {gone_code!r}"
    )
    assert gone_message == _proxy_not_found(good_proxy_name), gone_message
    dead_code, dead_message = _error_code(
        lambda: rds.modify_db_proxy(DBProxyName=good_proxy_name, IdleClientTimeout=1800)
    )
    assert dead_code == "DBProxyNotFoundFault", (
        f"expected modify_db_proxy on the deleted proxy {good_proxy_name!r} to fail with "
        f"DBProxyNotFoundFault, got {dead_code!r}"
    )
    assert dead_message == _proxy_not_found(good_proxy_name), dead_message


# ===== helpers =====


def _create_proxy(
    ctx, secret_arn: str, role_arn: str, subnet_ids: list[str], sg_id: str
) -> str:
    rds = ctx.client("rds")
    proxy_name = ctx.unique_name("sim2real-rdsproxy-good-")
    rds.create_db_proxy(
        DBProxyName=proxy_name,
        EngineFamily="MYSQL",
        Auth=[
            {"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}
        ],
        RoleArn=role_arn,
        VpcSubnetIds=subnet_ids,
        VpcSecurityGroupIds=[sg_id],
        RequireTLS=False,
    )
    ctx.on_cleanup(lambda: _delete_proxy(ctx, proxy_name))
    return proxy_name


def _proxy_not_found(proxy_name: str) -> str:
    return f"DBProxy '{proxy_name}' not found."


def _proxy_gone(rds, proxy_name: str) -> bool:
    """True once DescribeDBProxies refuses the name with DBProxyNotFoundFault; any other error raises."""
    from botocore.exceptions import ClientError

    try:
        rds.describe_db_proxies(DBProxyName=proxy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBProxyNotFoundFault":
            return True
        raise
    return False


def _error_code(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _default_vpc_network(ctx) -> tuple[list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError("no shared network VPC available to place the RDS Proxy")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "shared network VPC does not have subnets in at least 2 availability zones"
        )
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return list(by_az.values())[:2], sgs[0]["GroupId"]


def _create_throwaway_vpc_subnet(ctx) -> str:
    """A second, disposable VPC+subnet purely to construct a genuine cross-VPC subnet list
    for CreateDBProxy -- RDS Proxy requires all VpcSubnetIds to share one VPC."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rdsproxy-xvpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.212.0.0/24",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _poll_vpc_available(ctx, vpc_id, timeout_s=60)

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.212.0.0/28",
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return subnet_id


def _poll_vpc_available(ctx, vpc_id: str, timeout_s: float) -> None:
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
        if vpcs and vpcs[0]["State"] == "available":
            return
        time.sleep(2)
    raise AssertionError(f"throwaway VPC {vpc_id} never reached state 'available'")


def _create_secret(ctx, username: str, password: str) -> str:
    secrets = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-rdsproxy-secret-")
    resp = secrets.create_secret(
        Name=name,
        SecretString=json.dumps({"username": username, "password": password}),
    )
    arn = resp["ARN"]
    ctx.on_cleanup(
        lambda: secrets.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
    )
    return arn


def _create_proxy_role(ctx, allowed_secret_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rdsproxy-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "secrets-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": allowed_secret_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    _poll_role_readable(ctx, role_name, timeout_s=60)
    return role["Arn"], role_name


def _poll_role_readable(ctx, role_name: str, timeout_s: float) -> None:
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        role = iam.get_role(RoleName=role_name)["Role"]
        if role.get("RoleName") == role_name:
            return
        time.sleep(2)
    raise AssertionError(
        f"IAM role {role_name} never became readable within {timeout_s}s"
    )


def _delete_proxy(ctx, proxy_name: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_proxy(DBProxyName=proxy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBProxyNotFoundFault":
            raise
        return
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            rds.describe_db_proxies(DBProxyName=proxy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DBProxyNotFoundFault":
                raise
            return
        time.sleep(10)


def _poll_proxy_terminal_status(ctx, proxy_name: str, timeout_s: float) -> str:
    rds = ctx.client("rds")
    terminal = {"available", "incompatible-network", "insufficient-resource-limits"}
    deadline = time.monotonic() + timeout_s
    status: str | None = None
    while time.monotonic() < deadline:
        proxies = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"]
        status = proxies[0]["Status"] if proxies else None
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"{proxy_name!r} never left {status!r} within {timeout_s}s")


# EC2 network teardown: a resource in this VPC deletes asynchronously and its ENIs linger, so
# DeleteSubnet/DeleteSecurityGroup/DeleteVpc wait for them and retry DependencyViolation within one
# shared window, then raise naming the ENIs still attached; every other error propagates.
_NET_TEARDOWN_S = 1260.0
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
