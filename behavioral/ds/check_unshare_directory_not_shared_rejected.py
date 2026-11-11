"""unshare-directory-not-shared-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unshare-directory-not-shared-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Unsharing a directory with an account it was never shared with raises
    DirectoryNotSharedException; unsharing an account it actually is shared with
    succeeds.
    """
    directory_id = _create_microsoft_ad(ctx)
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    ds = ctx.client("ds")
    never_shared_account_id = "111122223333"

    # Break exactly one thing: unshare an account that was never shared with this directory.
    code, message, request_id = _error(
        lambda: ds.unshare_directory(
            DirectoryId=directory_id, UnshareTarget={"Id": never_shared_account_id, "Type": "ACCOUNT"}
        )
    )
    assert code == "DirectoryNotSharedException", f"expected DirectoryNotSharedException, got {code!r}"
    expected_message = (
        f"Directory {directory_id} is not shared with Account: {never_shared_account_id}. "
        f": RequestId: {request_id}"
    )
    assert message == expected_message, (
        f"the unshare must be refused with ds's exact message {expected_message!r}, got {message!r}"
    )

    # Effect absent: no share record exists for that account (there was never one to begin with).
    shares = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert not any(s["SharedAccountId"] == never_shared_account_id for s in shares), (
        f"expected no share record for {never_shared_account_id}, found one in {shares}"
    )

    # Positive control: share with a real target, then unshare it -- that succeeds.
    shared_account_id = "888899990000"
    ds.share_directory(
        DirectoryId=directory_id,
        ShareMethod="HANDSHAKE",
        ShareTarget={"Id": shared_account_id, "Type": "ACCOUNT"},
    )
    shares_after_share = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
    assert any(s["SharedAccountId"] == shared_account_id for s in shares_after_share), (
        f"expected a share record for {shared_account_id} after ShareDirectory, got {shares_after_share}"
    )

    ds.unshare_directory(DirectoryId=directory_id, UnshareTarget={"Id": shared_account_id, "Type": "ACCOUNT"})
    _wait_for_unshared(ctx, directory_id, shared_account_id)


# ===== helpers =====


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise.
    ds echoes the refused call's RequestId in its message. An unexpected SUCCESS raises instead of
    returning a falsy sentinel that would read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        request_id = (e.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_own_vpc_two_azs(ctx):
    ec2 = ctx.client("ec2")
    azs = sorted(
        az["ZoneName"]
        for az in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    )[:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose two available AZs to host a test directory")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": ctx.unique_name("ds-unshare-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": ctx.unique_name("ds-unshare-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, password="Sim2Real-TestPW1"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_own_vpc_two_azs(ctx)
    name = ctx.unique_name("sim2real-msad-") + ".test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=password,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": name}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ctx, directory_id))
    return directory_id


def _safe_delete_directory(ctx, directory_id):
    ds = ctx.client("ds")
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _directory_stage(ctx, directory_id):
    ds = ctx.client("ds")
    resp = ds.describe_directories(DirectoryIds=[directory_id])
    descs = resp["DirectoryDescriptions"]
    return descs[0]["Stage"] if descs else None


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=2700, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _directory_stage(ctx, directory_id)
        if last in target_stages:
            return last
        if last in ("Failed", "Impaired", "Inoperable") and last not in target_stages:
            raise AssertionError(f"directory {directory_id} reached unexpected stage {last}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={last})"
    )


def _wait_for_unshared(ctx, directory_id, account_id, timeout_s=180, interval_s=10):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        shares = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
        matching = [s for s in shares if s["SharedAccountId"] == account_id]
        if not matching or matching[0]["ShareStatus"] in ("Deleted",):
            return
        time.sleep(interval_s)
    raise AssertionError(f"share with {account_id} was never removed after UnshareDirectory")


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so a network
# delete waits (bounded, within the cleanup budget) for them and retries DependencyViolation, then
# raises naming the ENIs still attached. Teardown-only: run() never calls this.
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
