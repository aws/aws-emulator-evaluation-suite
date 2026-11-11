"""e2e-trust-create-verify-delete-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-trust-create-verify-delete-flow"
GROUP = "e2e"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Ds-Pw9!"
_TRUST_PASSWORD = "Sim2Real-Trust-Pw9!"
_DIR_ACTIVE_TIMEOUT_S = 3600.0
_TRUST_CREATED_TIMEOUT_S = 900.0
_TRUST_VERIFIED_TIMEOUT_S = 1800.0
_TRUST_DELETE_TIMEOUT_S = 900.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A trust relationship is created between two Managed Microsoft AD directories,
    verified, observed to actually transition to Verified state, then deleted and
    disappears from DescribeTrusts."""
    ds = ctx.client("ds")
    vpc = _create_vpc_with_subnets(ctx)

    domain_a = ctx.unique_name("sim2real-ds-trusta-").lower() + ".test"
    domain_b = ctx.unique_name("sim2real-ds-trustb-").lower() + ".test"

    # Distinct NetBIOS names: both DNS names share their first 15 characters, and a trust between
    # two domains with the same NetBIOS name fails ("cannot be performed on the current domain").
    dir_a = _create_microsoft_ad(ctx, ds, domain_a, "S2RTRUSTA", vpc)
    dir_b = _create_microsoft_ad(ctx, ds, domain_b, "S2RTRUSTB", vpc)

    desc_a = _wait_for_directory_stage(ctx, ds, dir_a, {"Active"}, _DIR_ACTIVE_TIMEOUT_S)
    desc_b = _wait_for_directory_stage(ctx, ds, dir_b, {"Active"}, _DIR_ACTIVE_TIMEOUT_S)
    dns_a = desc_a["DnsIpAddrs"]
    dns_b = desc_b["DnsIpAddrs"]
    assert dns_a and dns_b, (
        f"expected both directories to report DNS IPs once Active, got dns_a={dns_a!r} dns_b={dns_b!r}"
    )

    # Each directory gets its own AWS-managed security group that, by default, only admits
    # traffic from itself -- a same-VPC trust needs each side to also admit the other's AD
    # ports (DNS/Kerberos/LDAP/SMB/RPC), or CreateTrust deterministically dead-ends in Failed
    # before ever reaching Created.
    _allow_directory_to_directory_traffic(ctx, desc_a, desc_b)

    # Each side must be able to resolve the other's domain before a trust can verify.
    ds.create_conditional_forwarder(DirectoryId=dir_a, RemoteDomainName=domain_b, DnsIpAddrs=dns_b)
    ds.create_conditional_forwarder(DirectoryId=dir_b, RemoteDomainName=domain_a, DnsIpAddrs=dns_a)

    trust_id_a = ds.create_trust(
        DirectoryId=dir_a,
        RemoteDomainName=domain_b,
        TrustPassword=_TRUST_PASSWORD,
        TrustDirection="Two-Way",
    )["TrustId"]
    ctx.on_cleanup(lambda: _delete_trust_if_present(ds, trust_id_a))
    trust_id_b = ds.create_trust(
        DirectoryId=dir_b,
        RemoteDomainName=domain_a,
        TrustPassword=_TRUST_PASSWORD,
        TrustDirection="Two-Way",
    )["TrustId"]
    ctx.on_cleanup(lambda: _delete_trust_if_present(ds, trust_id_b))

    _wait_for_trust_state(ctx, ds, dir_a, trust_id_a, {"Created", "Verified"}, _TRUST_CREATED_TIMEOUT_S)
    _wait_for_trust_state(ctx, ds, dir_b, trust_id_b, {"Created", "Verified"}, _TRUST_CREATED_TIMEOUT_S)

    ds.verify_trust(TrustId=trust_id_a)
    final_state = _wait_for_trust_state(
        ctx, ds, dir_a, trust_id_a, {"Verified", "VerifyFailed"}, _TRUST_VERIFIED_TIMEOUT_S
    )
    assert final_state == "Verified", (
        f"expected trust {trust_id_a} to reach Verified after verify_trust, got {final_state}"
    )

    ds.delete_trust(TrustId=trust_id_a)
    ds.delete_trust(TrustId=trust_id_b)
    _wait_for_trust_gone(ctx, ds, dir_a, trust_id_a, _TRUST_DELETE_TIMEOUT_S)
    _wait_for_trust_gone(ctx, ds, dir_b, trust_id_b, _TRUST_DELETE_TIMEOUT_S)

    # A delete already asserted as gone still owes the mutation-on-dead-id beat: the
    # identical delete_trust call must now fail with the specific not-found code, not
    # merely stop appearing in a list.
    from botocore.exceptions import ClientError

    try:
        ds.delete_trust(TrustId=trust_id_a)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "EntityDoesNotExistException", (
            f"double-delete of trust {trust_id_a}: expected EntityDoesNotExistException, got {code}"
        )
        expected_message = f"Trust: {trust_id_a} does not exist : RequestId: {err.response['ResponseMetadata']['RequestId']}"
        message = err.response["Error"].get("Message")
        assert message == expected_message, f"expected {expected_message!r}, got {message!r}"
    else:
        raise AssertionError(f"double-delete of trust {trust_id_a} unexpectedly succeeded")

    remaining = ds.describe_trusts(DirectoryId=dir_a)["Trusts"]
    assert all(t["TrustId"] != trust_id_a for t in remaining), (
        f"expected trust {trust_id_a} absent from describe_trusts(DirectoryId={dir_a}), got {remaining!r}"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _allow_directory_to_directory_traffic(ctx, desc_a: dict, desc_b: dict) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    sg_a = desc_a["VpcSettings"]["SecurityGroupId"]
    sg_b = desc_b["VpcSettings"]["SecurityGroupId"]
    for sg_id, peer_sg_id in ((sg_a, sg_b), (sg_b, sg_a)):
        permissions = [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": peer_sg_id}]}]
        try:
            ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=permissions)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                raise
        # A rule naming the peer group keeps that group referenced, so Directory Service cannot
        # delete it with its directory and the VPC delete fails; revoke it before the directories go.
        ctx.on_cleanup(lambda g=sg_id, p=permissions: _revoke_ingress(ec2, g, p))


def _revoke_ingress(ec2, group_id, permissions) -> None:
    from botocore.exceptions import ClientError

    try:
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("InvalidGroup.NotFound", "InvalidPermission.NotFound"):
            raise


def _create_microsoft_ad(ctx, ds, domain, short_name, vpc) -> str:
    directory_id = ds.create_microsoft_ad(
        Name=domain,
        ShortName=short_name,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc["vpc_id"], "SubnetIds": vpc["subnet_ids"]},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: ds.delete_directory(DirectoryId=directory_id))
    return directory_id


def _wait_for_directory_stage(ctx, ds, directory_id, target_stages, timeout_s, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} entered terminal stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s "
        f"(last stage={stage})"
    )


def _wait_for_trust_state(ctx, ds, directory_id, trust_id, target_states, timeout_s, interval_s=15.0):
    # Real AWS rejects DescribeTrusts(TrustIds=[...]) alone with InvalidParameterException
    # ("Directory ID must be specified") even though botocore's own client-side model marks
    # neither DirectoryId nor TrustIds as required -- DirectoryId must always be passed.
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        trust = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"][0]
        state = trust["TrustState"]
        if state in target_states:
            return state
        if state == "Failed":
            raise AssertionError(
                f"trust {trust_id} entered Failed, reason={trust.get('TrustStateReason')!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"trust {trust_id} did not reach {target_states} within {timeout_s}s (last={state})")


def _wait_for_trust_gone(ctx, ds, directory_id, trust_id, timeout_s, interval_s=15.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            trusts = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not trusts or trusts[0]["TrustState"] == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust {trust_id} was not deleted within {timeout_s}s")


def _delete_trust_if_present(ds, trust_id) -> None:
    from botocore.exceptions import ClientError

    try:
        ds.delete_trust(TrustId=trust_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


# EC2 network teardown: a directory, endpoint or instance deletes asynchronously, so its ENIs can hold
# the subnet / VPC (DependencyViolation). Wait for the ENIs to go and retry DependencyViolation inside
# one window shared by the check's network deletes, then raise naming the ENIs; other errors propagate.
_NET_TEARDOWN_S = 1500.0
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
