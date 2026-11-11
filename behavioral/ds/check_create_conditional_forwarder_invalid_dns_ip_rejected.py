"""create-conditional-forwarder-invalid-dns-ip-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-conditional-forwarder-invalid-dns-ip-rejected"
GROUP = "overly-permissive"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConditionalForwarder with an out-of-range DnsIpAddrs octet is rejected with
    ValidationException and the exact pattern-constraint message and creates no forwarder,
    while a well-formed DNS IP for a different remote domain still succeeds."""
    ds = ctx.client("ds")
    directory_id = _create_active_microsoft_ad(ctx)

    bad_domain = f"{ctx.unique_name('sim2real-ds-bad-')}.test"
    code, message = _error(
        lambda: ds.create_conditional_forwarder(
            DirectoryId=directory_id,
            RemoteDomainName=bad_domain,
            DnsIpAddrs=["999.999.999.999"],
        )
    )
    assert code == "ValidationException", f"unexpected error code: {code}"
    expected_message = (
        "1 validation error detected: Value '[999.999.999.999]' at 'dnsIpAddrs' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must satisfy regular "
        "expression pattern: ^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
        "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$]"
    )
    assert message == expected_message, f"unexpected error message: {message!r}"

    existing_domains = {
        cf["RemoteDomainName"]
        for cf in ds.describe_conditional_forwarders(DirectoryId=directory_id)["ConditionalForwarders"]
    }
    assert bad_domain not in existing_domains, (
        f"the rejected CreateConditionalForwarder must not have persisted a forwarder for {bad_domain}"
    )

    # Positive control: a well-formed DNS IP for a different remote domain succeeds,
    # proving the operation itself is not globally broken.
    good_domain = f"{ctx.unique_name('sim2real-ds-good-')}.test"
    _retry_directory_busy(
        lambda: ds.create_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=good_domain, DnsIpAddrs=["10.0.5.5"]
        )
    )
    ctx.on_cleanup(
        lambda: _safe_delete_conditional_forwarder(ds, directory_id, good_domain)
    )
    after_domains = {
        cf["RemoteDomainName"]
        for cf in ds.describe_conditional_forwarders(DirectoryId=directory_id)["ConditionalForwarders"]
    }
    assert good_domain in after_domains, (
        f"expected {good_domain!r} in {after_domains!r} after the positive-control create"
    )
    assert bad_domain not in after_domains, (
        f"expected {bad_domain!r} absent from {after_domains!r}; the rejected forwarder must not appear"
    )


# ===== helpers =====


def _create_vpc_with_subnets(ctx) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-ds-")
    vpc = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:2]
    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.0.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{tag}{i}"}]}
            ],
        )
        subnet_ids.append(subnet["Subnet"]["SubnetId"])

    def _cleanup() -> None:
        for sid in subnet_ids:
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_active_microsoft_ad(ctx) -> str:
    ds = ctx.client("ds")
    net = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password="TestPassw0rd!2345",
        VpcSettings={"VpcId": net["vpc_id"], "SubnetIds": net["subnet_ids"]},
    )
    directory_id = resp["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ds, directory_id))
    stage = _wait_for_directory_stage(
        ds, directory_id, {"Active", "Failed", "Impaired"}, timeout_s=3600.0, interval_s=30.0
    )
    if stage != "Active":
        raise AssertionError(f"prerequisite Microsoft AD directory did not reach Active (got {stage!r})")
    return directory_id


def _wait_for_directory_stage(
    ds, directory_id: str, target_stages: set[str], timeout_s: float = 3600.0, interval_s: float = 30.0
) -> str | None:
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            return None
        last_stage = descs[0]["Stage"]
        if last_stage in target_stages:
            return last_stage
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach {target_stages}, last stage={last_stage}")


def _error(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _retry_directory_busy(fn, attempts: int = 10, delay_s: float = 15.0):
    """A directory that has just reached Active can still answer a mutating call with
    DirectoryUnavailableException or ServiceException for a short while. Retry a bounded
    number of times, then re-raise the last error."""
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("DirectoryUnavailableException", "ServiceException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _safe_delete_conditional_forwarder(ds, directory_id: str, remote_domain: str) -> None:
    try:
        ds.delete_conditional_forwarder(DirectoryId=directory_id, RemoteDomainName=remote_domain)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _safe_delete_directory(ds, directory_id: str) -> None:
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise
        return
    deadline = time.monotonic() + 1140.0  # with the 630 s network teardown, fits the 1800 s budget
    while time.monotonic() < deadline:
        try:
            resp = ds.describe_directories(DirectoryIds=[directory_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise
            return
        descs = resp.get("DirectoryDescriptions", [])
        if not descs or descs[0]["Stage"] == "Deleted":
            return
        time.sleep(30.0)
    raise AssertionError(f"directory {directory_id} still exists 1140s after DeleteDirectory")


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
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
