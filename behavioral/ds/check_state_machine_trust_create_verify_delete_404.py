"""state-machine-trust-create-verify-delete-404."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "state-machine-trust-create-verify-delete-404"
GROUP = "state-machine"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!Test2024"
_TRUST_PASSWORD = "Sim2RealTrust!2024"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A two-way trust between two Managed Microsoft AD domains reaches Created, then Verified
    after VerifyTrust; after DeleteTrust, DescribeTrusts eventually reports the trust gone.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/API_VerifyTrust.html"""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_and_subnets(ctx)

    # Create both before waiting: each takes 20-45 minutes, and they provision in parallel.
    dir1_id, domain1 = _create_microsoft_ad(ctx, vpc_id, subnet_ids, "sim2realtrust1")
    dir2_id, domain2 = _create_microsoft_ad(ctx, vpc_id, subnet_ids, "sim2realtrust2")
    _wait_directory_stage(ctx, dir1_id, {"Active"})
    _wait_directory_stage(ctx, dir2_id, {"Active"})

    dns1 = ds.describe_directories(DirectoryIds=[dir1_id])["DirectoryDescriptions"][0]["DnsIpAddrs"]
    dns2 = ds.describe_directories(DirectoryIds=[dir2_id])["DirectoryDescriptions"][0]["DnsIpAddrs"]

    ds.create_conditional_forwarder(DirectoryId=dir1_id, RemoteDomainName=domain2, DnsIpAddrs=dns2)
    ctx.on_cleanup(lambda: _safe_delete_forwarder(ctx, dir1_id, domain2))
    ds.create_conditional_forwarder(DirectoryId=dir2_id, RemoteDomainName=domain1, DnsIpAddrs=dns1)
    ctx.on_cleanup(lambda: _safe_delete_forwarder(ctx, dir2_id, domain1))

    # The remote side must have its own trust object with the matching password before the
    # local side can be verified.
    ds.create_trust(
        DirectoryId=dir2_id,
        RemoteDomainName=domain1,
        TrustPassword=_TRUST_PASSWORD,
        TrustDirection="Two-Way",
    )
    trust1_id = ds.create_trust(
        DirectoryId=dir1_id,
        RemoteDomainName=domain2,
        TrustPassword=_TRUST_PASSWORD,
        TrustDirection="Two-Way",
    )["TrustId"]

    trust_deleted = {"value": False}

    def _cleanup_trust():
        if trust_deleted["value"]:
            return
        try:
            ds.delete_trust(TrustId=trust1_id, DeleteAssociatedConditionalForwarder=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup_trust)

    # With the remote side's trust already in place, AWS can verify the new trust on its own and
    # move it past Created to Verified between two polls; both mean the trust was created.
    _wait_for_trust_state(ctx, dir1_id, trust1_id, {"Created", "Verified"}, timeout_s=600)
    ds.verify_trust(TrustId=trust1_id)
    _wait_for_trust_state(ctx, dir1_id, trust1_id, {"Verified"}, timeout_s=1200)

    ds.delete_trust(TrustId=trust1_id, DeleteAssociatedConditionalForwarder=True)
    trust_deleted["value"] = True

    # DescribeTrusts without DirectoryId answers an unresolvable id (deleted ones included) with
    # InvalidParameterException("Directory ID must be specified"), so the DirectoryId is always passed.
    code, message, request_id = _wait_for_trust_not_found(ctx, dir1_id, trust1_id, timeout_s=600)
    assert code == "EntityDoesNotExistException", f"expected a deleted trust to 404, got {code}: {message}"
    expected_message = f"Trust: {trust1_id} does not exist : RequestId: {request_id}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _tag_spec(resource_type: str, name: str) -> list:
    return [{
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    }]


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-trust-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.92.0.0/16", TagSpecifications=_tag_spec("vpc", name))[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for DS directories")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.92.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", f"{name}-{i}"),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _wait_directory_stage(ctx, directory_id, target_stages, timeout_s=3600, interval_s=30):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory entered terminal failure stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(f"directory did not reach {target_stages} within {timeout_s}s (last={stage})")


def _create_microsoft_ad(ctx, vpc_id, subnet_ids, name_prefix):
    ds = ctx.client("ds")
    name = f"{ctx.unique_name(name_prefix)}.test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    )["DirectoryId"]

    def _cleanup():
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup)
    return directory_id, name


def _wait_for_trust_state(ctx, directory_id, trust_id, target_states, timeout_s=600, interval_s=15):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        trust = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"][0]
        state = trust["TrustState"]
        if state in target_states:
            return trust
        if state in ("VerifyFailed", "Failed"):
            raise AssertionError(f"trust entered failure state {state}")
        time.sleep(interval_s)
    raise AssertionError(f"trust never reached {target_states} (last={state})")


def _wait_for_trust_not_found(ctx, directory_id, trust_id, timeout_s=600, interval_s=10):
    """Poll DescribeTrusts through the Deleting/Deleted stages until it refuses the trust with
    EntityDoesNotExistException; return that refusal's (code, message, request id). Any other
    answer keeps polling; at the deadline it raises with the last one."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            trusts = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"]
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "EntityDoesNotExistException":
                return error["Code"], error.get("Message", ""), exc.response["ResponseMetadata"]["RequestId"]
            last = f"{error['Code']}: {error.get('Message', '')}"
        else:
            last = f"states={[t.get('TrustState') for t in trusts]}"
        time.sleep(interval_s)
    raise AssertionError(f"DescribeTrusts did not refuse the deleted trust within {timeout_s}s (last answer: {last})")


def _safe_delete_forwarder(ctx, directory_id, remote_domain_name):
    try:
        ctx.client("ds").delete_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=remote_domain_name
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


# Asynchronously deleted resources (load balancers, directories, endpoints, ...) leave ENIs in the
# subnet / security group for a while, so an immediate delete fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry DependencyViolation in the same window, then raise naming the
# ENIs still attached. The window is shared by all of one check's network deletes.
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
