"""create-trust-duplicate-remote-domain-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-trust-duplicate-remote-domain-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second trust for an already-trusted remote domain is rejected with EntityAlreadyExistsException
    and AWS's trust-exists message and creates no second record, while a different remote domain can
    still be trusted and, once the original trust is deleted, the same domain again."""
    directory_id = _create_active_microsoft_ad(ctx)
    ds = ctx.client("ds")

    remote_domain = f"{ctx.unique_name('sim2real-ds-dup-')}.test"
    trust_id_1 = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=remote_domain,
        TrustPassword="TrustPassw0rd!2345",
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]
    ctx.on_cleanup(lambda: _safe_delete_trust(ds, trust_id_1))

    code, message, request_id = _error(
        lambda: ds.create_trust(
            DirectoryId=directory_id,
            RemoteDomainName=remote_domain,
            TrustPassword="TrustPassw0rd!2345",
            TrustDirection="One-Way: Outgoing",
        )
    )
    assert code == "EntityAlreadyExistsException", f"unexpected error code: {code}"
    assert message == (
        f"Trust already exists for directory: {directory_id} and remote domain: {remote_domain}. "
        f": RequestId: {request_id}"
    ), f"unexpected EntityAlreadyExistsException message: {message!r}"

    trusts_for_domain = [
        t
        for t in ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
        if t["RemoteDomainName"] == remote_domain
    ]
    assert len(trusts_for_domain) == 1, (
        f"expected exactly 1 trust for {remote_domain}, found {len(trusts_for_domain)}"
    )
    assert trusts_for_domain[0]["TrustId"] == trust_id_1, (
        f"expected the surviving trust for {remote_domain} to be {trust_id_1}, "
        f"found {trusts_for_domain[0]['TrustId']}"
    )

    # Positive control: a trust to a genuinely different remote domain on the same
    # directory succeeds, proving CreateTrust itself is not globally broken.
    other_domain = f"{ctx.unique_name('sim2real-ds-other-')}.test"
    trust_id_2 = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=other_domain,
        TrustPassword="TrustPassw0rd!2345",
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]
    ctx.on_cleanup(lambda: _safe_delete_trust(ds, trust_id_2))
    assert trust_id_2 != trust_id_1, f"expected a fresh trust id, got the original {trust_id_1} back"

    all_trusts = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
    domains = {t["RemoteDomainName"] for t in all_trusts}
    assert remote_domain in domains and other_domain in domains, (
        f"expected both {remote_domain} and {other_domain} to be visible, found {domains}"
    )

    # Restore: delete the original trust, freeing the remote domain, and prove the identical
    # CreateTrust call then succeeds against the same directory. DeleteTrust needs the trust past its
    # transient Creating/Verifying phase first. An unresolvable .test remote domain
    # deterministically lands TrustState=Failed rather than VerifyFailed, so that is part of the
    # terminal set alongside the states a resolvable domain reaches.
    _wait_for_trust_state(
        ctx,
        ds,
        directory_id,
        trust_id_1,
        {"Created", "Verified", "VerifyFailed", "Failed"},
        timeout_s=900.0,
    )
    ds.delete_trust(TrustId=trust_id_1)
    _wait_for_trust_gone(ctx, ds, directory_id, trust_id_1, timeout_s=900.0)

    trusts_after_delete = [
        t
        for t in ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
        if t["RemoteDomainName"] == remote_domain
    ]
    assert trusts_after_delete == [], (
        f"expected no trust for {remote_domain} after deleting {trust_id_1}, "
        f"found {trusts_after_delete}"
    )

    trust_id_3 = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=remote_domain,
        TrustPassword="TrustPassw0rd!2345",
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]
    ctx.on_cleanup(lambda: _safe_delete_trust(ds, trust_id_3))
    assert trust_id_3 != trust_id_1, f"expected a fresh trust id, got the deleted {trust_id_1} back"


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

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    az_names = [az["ZoneName"] for az in azs if az.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS][:2]
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
    stage = _wait_for_directory_stage(ctx, ds, directory_id, {"Active", "Failed", "Impaired"}, timeout_s=3600.0)
    if stage != "Active":
        raise AssertionError(f"prerequisite Microsoft AD directory did not reach Active (got {stage!r})")
    return directory_id


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_directory_stage(ctx, ds, directory_id: str, target_stages: set[str], timeout_s: float) -> str | None:
    timeout_s = _budget_s(ctx, timeout_s)
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
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"directory {directory_id} reaching {target_stages}: the run budget ended first; not graded")
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s:.0f}s, last stage={last_stage}"
    )


def _wait_for_trust_state(
    ctx,
    ds,
    directory_id: str,
    trust_id: str,
    target_states: set[str],
    timeout_s: float,
) -> str:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        trusts = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
        match = next((t for t in trusts if t["TrustId"] == trust_id), None)
        if match is None:
            raise AssertionError(f"trust {trust_id} disappeared while waiting for {target_states}")
        last_state = match["TrustState"]
        if last_state in target_states:
            return last_state
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"trust {trust_id} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"trust {trust_id} did not reach {target_states} within {timeout_s:.0f}s, last state={last_state!r}")


def _wait_for_trust_gone(ctx, ds, directory_id: str, trust_id: str, timeout_s: float) -> None:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        trusts = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
        match = next((t for t in trusts if t["TrustId"] == trust_id), None)
        if match is None or match["TrustState"] == "Deleted":
            return
        last_state = match["TrustState"]
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"trust {trust_id} disappearing: the run budget ended first; not graded")
    raise AssertionError(f"trust {trust_id} did not disappear within {timeout_s:.0f}s, last state={last_state!r}")


def _error(fn):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", ""), exc.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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
        time.sleep(2.0)
    raise AssertionError(f"directory {directory_id} still exists 1140s after DeleteDirectory")


def _safe_delete_trust(ds, trust_id: str) -> None:
    try:
        ds.delete_trust(TrustId=trust_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


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
