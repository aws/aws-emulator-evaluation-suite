"""trust-create-delete-lifecycle."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrust registers a trust visible in DescribeTrusts; DeleteTrust removes it
    from the trust inventory."""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_two_subnets(ctx)
    directory_id = _create_active_microsoft_ad(ctx, ds, vpc_id, subnet_ids)

    remote_domain = f"{ctx.unique_name('sim2real-remote-')}.example.com"
    trust_id = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=remote_domain,
        TrustPassword=_ad_password(),
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]

    deleted = {"done": False}

    def _cleanup_trust():
        if deleted["done"]:
            return
        _best_effort(lambda: ds.delete_trust(TrustId=trust_id))

    ctx.on_cleanup(_cleanup_trust)

    trusts = _poll_until(
        lambda: ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"],
        lambda ts: len(ts) == 1,
        timeout_s=120.0,
        interval_s=5.0,
    )
    trust = trusts[0]
    assert trust["TrustId"] == trust_id, f"expected TrustId {trust_id!r}, got {trust['TrustId']!r}"
    assert trust["RemoteDomainName"] == remote_domain, (
        f"expected RemoteDomainName {remote_domain!r}, got {trust['RemoteDomainName']!r}"
    )
    assert trust["TrustState"] in (
        "Creating",
        "Created",
        "Verifying",
        "Verified",
        "VerifyFailed",
    ), trust["TrustState"]

    ds.delete_trust(TrustId=trust_id)
    deleted["done"] = True

    def _gone() -> bool:
        try:
            ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])
        except ClientError as err:
            return err.response["Error"]["Code"] == "EntityDoesNotExistException"
        return False

    _poll_until(_gone, lambda ok: ok is True, timeout_s=900.0, interval_s=15.0)

    mutate_code = _error_code(lambda: ds.verify_trust(TrustId=trust_id))
    assert mutate_code == "EntityDoesNotExistException", (
        f"VerifyTrust on a deleted TrustId should 404, got code={mutate_code!r}"
    )


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """The error code fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ad_password() -> str:
    return "Sim2Real!" + secrets.token_hex(8) + "Aa1"


def _tag_spec(ctx, resource_type: str, kind: str):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-{kind}-")}],
    }


def _create_vpc_with_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.173.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]

    def _cleanup_vpc():
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_vpc)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError("region does not have 2 available AZs")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.173.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _cleanup_subnet(sid=subnet_id):
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise

        ctx.on_cleanup(_cleanup_subnet)
    return vpc_id, subnet_ids


def _create_active_microsoft_ad(ctx, ds, vpc_id, subnet_ids) -> str:
    name = f"{ctx.unique_name('sim2real-msad-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_ad_password(),
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-directory-")}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ds.delete_directory(DirectoryId=directory_id)))

    stage = _poll_until(
        lambda: ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=5400.0,
        interval_s=30.0,
    )
    if stage != "Active":
        raise AssertionError(f"directory reached terminal stage {stage!r} instead of Active")
    return directory_id


# EC2 network teardown: a directory, endpoint or instance deletes asynchronously, so its ENIs can hold
# the subnet / VPC (DependencyViolation). Wait for the ENIs to go and retry DependencyViolation inside
# one window shared by the check's network deletes, then raise naming the ENIs; other errors propagate.
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
