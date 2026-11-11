"""create-db-proxy-invalid-subnet-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-db-proxy-invalid-subnet-rejected"
GROUP = "negative-classes"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDBProxy with VpcSubnetIds spanning two VPCs fails InvalidParameterCombination and leaves
    no proxy; the same request with subnets of one VPC succeeds and reaches 'available'.
    """
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    vpc_a, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_a1, subnet_a2 = az_subnets[0]["SubnetId"], az_subnets[1]["SubnetId"]
    az_for_b = az_subnets[0]["AvailabilityZone"]

    # A throwaway second VPC, so the "outside subnet" is genuinely in a different VPC than the
    # proxy's own VpcSubnetIds -- not just an unrelated/nonexistent subnet ID.
    vpc_b = ec2.create_vpc(
        CidrBlock="10.199.0.0/24", TagSpecifications=[{"ResourceType": "vpc", "Tags": _MANAGED_TAGS}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_b))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_b], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_b = ec2.create_subnet(
        VpcId=vpc_b,
        CidrBlock="10.199.0.0/25",
        AvailabilityZone=az_for_b,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _MANAGED_TAGS}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_b))

    # A real, assumable role + a real secret: CreateDBProxy is otherwise unattributable -- a
    # nonexistent RoleArn/SecretArn would leave the positive control stuck short of "available"
    # for a reason that has nothing to do with the subnet contract under test.
    role_arn, secret_arn = _create_proxy_prerequisites(ctx)
    auth = [{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}]

    # --- negative: subnets spanning two distinct VPCs ---
    bad_name = ctx.unique_name("sim2real-rdsproxy-bad-")
    # Registered before the call: an over-permissive target that creates it must not leak it.
    ctx.on_cleanup(lambda: _delete_proxy_if_present(rds, bad_name))
    code, message = _error(
        lambda: _create_proxy_when_role_ready(
            rds,
            DBProxyName=bad_name,
            EngineFamily="MYSQL",
            Auth=auth,
            RoleArn=role_arn,
            VpcSubnetIds=[subnet_a1, subnet_b],
        )
    )
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for VpcSubnetIds spanning two VPCs, got {code!r}"
    )
    # AWS lists the two VPCs in no fixed order, so the message is matched with either order.
    prefix = "Subnets must belong to only one VPC but found multiple VPCs: "
    expected = {f"{prefix}[{first}, {second}]" for first, second in ((vpc_a, vpc_b), (vpc_b, vpc_a))}
    assert message in expected, f"expected message one of {sorted(expected)!r}, got {message!r}"

    # Effect absent: the rejected proxy must not exist afterwards.
    not_found_code, not_found_message = _error(
        lambda: rds.describe_db_proxies(DBProxyName=bad_name)
    )
    assert not_found_code == "DBProxyNotFoundFault", (
        f"rejected proxy {bad_name!r} should not exist, but describe returned "
        f"code={not_found_code!r} instead of DBProxyNotFoundFault"
    )
    expected_nf = f"DBProxy '{bad_name}' not found."
    assert not_found_message == expected_nf, (
        f"expected message {expected_nf!r}, got {not_found_message!r}"
    )

    # --- positive control: subnets all within the same VPC succeed and provision ---
    good_name = ctx.unique_name("sim2real-rdsproxy-good-")
    _create_proxy_when_role_ready(
        rds,
        DBProxyName=good_name,
        EngineFamily="MYSQL",
        Auth=auth,
        RoleArn=role_arn,
        VpcSubnetIds=[subnet_a1, subnet_a2],
    )

    # Fast, non-blocking fallback: ctx.on_cleanup gets a single (bounded, cheap) 60s budget
    # shared by every registered teardown, so a delete-and-poll here would starve the role/
    # secret/subnet/vpc cleanups queued behind it. The real delete-and-verify happens as an
    # explicit body step below, on the check's own (much larger) budget.
    ctx.on_cleanup(lambda: _delete_proxy_if_present(rds, good_name))

    deadline = time.monotonic() + 900
    status = None
    while time.monotonic() < deadline:
        status = rds.describe_db_proxies(DBProxyName=good_name)["DBProxies"][0]["Status"]
        if status == "available":
            break
        time.sleep(2)
    assert status == "available", (
        f"positive-control proxy {good_name!r} never reached 'available' within 900s "
        f"(last status={status!r})"
    )

    # --- teardown of the positive control, proven rather than assumed ---
    rds.delete_db_proxy(DBProxyName=good_name)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if not _proxy_exists(rds, good_name):
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"positive-control proxy {good_name!r} still describable 300s after delete_db_proxy"
        )
    # Gone means unusable too: a mutation on the dead id must fail the same way.
    dead_code, dead_message = _error(
        lambda: rds.modify_db_proxy(DBProxyName=good_name, IdleClientTimeout=1800)
    )
    assert dead_code == "DBProxyNotFoundFault", (
        f"modify_db_proxy on deleted proxy {good_name!r} should be DBProxyNotFoundFault, "
        f"got {dead_code!r}"
    )
    expected_dead = f"DBProxy '{good_name}' not found."
    assert dead_message == expected_dead, (
        f"expected message {expected_dead!r}, got {dead_message!r}"
    )



def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
    """Return (vpc_id, [subnet, ...]) covering `count` distinct AZs, for a DBSubnetGroup/proxy."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < count:
        raise AssertionError(
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for this test"
        )
    return vpc_id, list(by_az.values())[:count]


def _cleanup_role(iam, role_name: str) -> None:
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_proxy_prerequisites(ctx) -> tuple[str, str]:
    """Create a real IAM role (trusted by rds.amazonaws.com) + Secrets Manager secret a DB
    proxy can actually assume/read. Returns (role_arn, secret_arn); all teardown is registered
    on ctx."""
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _cleanup_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="secrets",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue", "kms:Decrypt"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    sm = ctx.client("secretsmanager")
    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-rdsproxy-secret-"),
        SecretString=json.dumps({"username": "sim2real", "password": "Sim2Real#Pass99"}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True)
    )
    return role["Role"]["Arn"], secret["ARN"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_proxy_when_role_ready(rds, timeout_s: float = 120.0, **kwargs) -> dict:
    """CreateDBProxy, retrying the refusal a freshly created role gets until IAM propagates it;
    raises on timeout or on any other error."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.create_db_proxy(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _proxy_exists(rds, name: str) -> bool:
    from botocore.exceptions import ClientError

    try:
        rds.describe_db_proxies(DBProxyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBProxyNotFoundFault":
            return False
        raise
    return True


def _delete_proxy_if_present(rds, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_proxy(DBProxyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBProxyNotFoundFault", "InvalidDBProxyStateFault"):
            raise


# Async deletes (ELB, endpoint, instance, ...) leave ENIs behind, so DeleteSubnet/SecurityGroup/Vpc
# fail DependencyViolation for a while: wait (bounded) for the ENIs to go and retry within the
# window, then raise naming the ENIs still attached.
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
