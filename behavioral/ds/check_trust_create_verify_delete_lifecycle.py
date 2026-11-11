"""trust-create-verify-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trust-create-verify-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A trust to an unreachable remote domain settles in TrustState=Failed with a reason,
    VerifyTrust on it is rejected naming that state, and DeleteTrust then makes DescribeTrusts 404.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/ms_ad_setup_trust.html
    """
    ds = ctx.client("ds")
    directory_id = _get_or_create_shared_microsoft_ad(ctx)

    remote_domain = f"{ctx.unique_name('unreachable-remote-')}.invalid"
    resp = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=remote_domain,
        TrustPassword="Sim2Real-Trust!9Qx",
        TrustDirection="One-Way: Outgoing",
        ConditionalForwarderIpAddrs=["203.0.113.5"],
    )
    trust_id = resp["TrustId"]
    ctx.on_cleanup(lambda: _delete_trust_and_wait(ctx, directory_id, trust_id))

    settled = _wait_trust_state(ctx, directory_id, trust_id, {"Failed"}, {"Verified", "VerifyFailed"})
    assert settled["TrustState"] == "Failed", (
        f"expected trust {trust_id} to settle at Failed against an unreachable remote domain, got "
        f"{settled['TrustState']!r}"
    )
    assert settled.get("TrustStateReason"), (
        f"a Failed trust must carry a diagnostic in TrustStateReason, got {settled!r}"
    )
    assert settled["RemoteDomainName"] == remote_domain, (
        f"DescribeTrusts reports RemoteDomainName {settled.get('RemoteDomainName')!r}, expected "
        f"{remote_domain!r} -- the trust under test must be the one that was created"
    )

    err = _client_error(lambda: ds.verify_trust(TrustId=trust_id))
    assert err is not None, "VerifyTrust on a Failed trust must be refused, it returned successfully"
    assert err["Code"] == "InvalidParameterException", (
        f"expected InvalidParameterException from VerifyTrust on a Failed trust, got {err!r}"
    )
    assert "Failed" in (err.get("Message") or ""), (
        f"the refusal must name the state it refused from, got {err.get('Message')!r}"
    )

    unchanged = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"][0]
    assert unchanged["TrustState"] == "Failed", (
        f"the refused VerifyTrust changed TrustState to {unchanged['TrustState']!r}"
    )

    _delete_trust_and_wait(ctx, directory_id, trust_id)
    try:
        ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])
    except ClientError as exc:
        gone, request_id = exc.response.get("Error", {}), exc.response["ResponseMetadata"]["RequestId"]
    else:
        gone = request_id = None
    assert gone is not None and gone["Code"] == "EntityDoesNotExistException", (
        f"expected DescribeTrusts for the deleted trust {trust_id} to raise "
        f"EntityDoesNotExistException, got {gone!r}"
    )
    expected = f"Trust: {trust_id} does not exist : RequestId: {request_id}"
    assert gone.get("Message") == expected, f"expected message {expected!r}, got {gone.get('Message')!r}"


def _ds_password() -> str:
    return "Sim2Real-Behav!9Qx"


def _client_error(fn):
    """The botocore Error dict the call raised, or None when it succeeded."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    return None


def _tag_spec(rtype: str, name: str) -> list:
    return [{
        "ResourceType": rtype,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "ds-behavioral"}],
    }]


def _create_vpc_with_subnets(ctx, cidr: str = "10.95.0.0/16"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=_tag_spec("vpc", ctx.unique_name("sim2real-ds-vpc-"))
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_ec2_retrying(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.95.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", ctx.unique_name(f"sim2real-ds-subnet{i}-")),
        )["Subnet"]["SubnetId"]
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        ctx.on_cleanup(lambda sid=subnet_id: _delete_ec2_retrying(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _delete_ec2_retrying(fn, attempts: int = 12, delay_s: float = 15.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("DependencyViolation", "InvalidParameterValue"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    if last_exc:
        raise last_exc


def _wait_directory_stage(ctx, directory_id, terminal_ok, terminal_bad, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        resp = ds.describe_directories(DirectoryIds=[directory_id])
        descs = resp.get("DirectoryDescriptions", [])
        if not descs:
            raise AssertionError(f"directory {directory_id} vanished from DescribeDirectories while waiting")
        desc = descs[0]
        last_stage = desc["Stage"]
        if last_stage in terminal_ok:
            return desc
        if last_stage in terminal_bad:
            raise AssertionError(f"directory {directory_id} reached {last_stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage={last_stage} after {timeout_s}s")


_SHARED_MAD_NAME = "sim2dssharedmad.sim2real.test"
_SHARED_VPC_TAG_NAME = "sim2real-ds-shared-vpc"


def _find_directory_id_by_name(ctx, name):
    ds = ctx.client("ds")
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = ds.describe_directories(**kwargs)
        for desc in resp.get("DirectoryDescriptions", []):
            if desc.get("Name") == name and desc.get("Stage") not in ("Deleting", "Deleted"):
                return desc["DirectoryId"]
        next_token = resp.get("NextToken")
        if not next_token:
            return None


def _get_or_create_shared_vpc(ctx):
    """Look up the shared VPC by tag before creating one, so concurrent checks converge on a
    single VPC instead of exhausting the per-region VPC quota. Deliberately registers no cleanup."""
    ec2 = ctx.client("ec2")

    def _existing():
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [_SHARED_VPC_TAG_NAME]}])["Vpcs"]
        return sorted((v for v in vpcs if v["State"] != "deleting"), key=lambda v: v["VpcId"])

    vpcs = _existing()
    create_exc = None
    if not vpcs:
        try:
            ec2.create_vpc(
                CidrBlock="10.90.0.0/16",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": _SHARED_VPC_TAG_NAME},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )
        except ClientError as exc:
            create_exc = exc
        for _ in range(15):
            vpcs = _existing()
            if vpcs:
                break
            time.sleep(2)
    if not vpcs:
        detail = f": {create_exc.response.get('Error', {})}" if create_exc is not None else " (no CreateVpc error, but none visible on lookback either)"
        raise AssertionError(f"failed to create or find the shared sim2real-ds VPC{detail}")
    vpc_id = vpcs[0]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    if len(subnet_ids) >= 2:
        return vpc_id, subnet_ids[:2]

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    for i, az in enumerate(azs):
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=f"10.90.{i}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": f"{_SHARED_VPC_TAG_NAME}-subnet{i}"},
                        {"Key": "sim2real", "Value": "ds-behavioral"},
                    ],
                }],
            )["Subnet"]["SubnetId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                continue
            raise
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
        subnet_ids = [s["SubnetId"] for s in subnets if s["State"] == "available"]
    return vpc_id, subnet_ids[:2]


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _get_or_create_shared_microsoft_ad(ctx) -> str:
    """Reuse a shared Managed Microsoft AD directory rather than paying ~20-45 min to reach Active
    per check. Not torn down here; waits for Active to an AWS-plausible deadline capped by the
    runner's remaining time."""
    ds = ctx.client("ds")
    directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
    if directory_id is None:
        vpc_id, subnet_ids = _get_or_create_shared_vpc(ctx)
        try:
            resp = ds.create_microsoft_ad(
                Name=_SHARED_MAD_NAME,
                Password=_ds_password(),
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExistsException":
                directory_id = _find_directory_id_by_name(ctx, _SHARED_MAD_NAME)
                if directory_id is None:
                    raise
            else:
                raise
    return _wait_directory_stage(
        ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=_budget_s(ctx, 3600.0), interval_s=10.0
    )["DirectoryId"]


def _wait_trust_state(ctx, directory_id, trust_id, terminal_ok, terminal_bad, timeout_s=200.0, interval_s=10.0):
    # DescribeTrusts requires DirectoryId: a TrustIds-only call is refused with
    # InvalidParameterException "Directory ID must be specified."
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])
        trusts = resp.get("Trusts", [])
        if not trusts:
            raise AssertionError(f"trust {trust_id} vanished from DescribeTrusts while waiting")
        trust = trusts[0]
        last = trust["TrustState"]
        if last in terminal_ok:
            return trust
        if last in terminal_bad:
            raise AssertionError(
                f"trust {trust_id} reached {last}, expected one of {sorted(terminal_ok)}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"trust {trust_id} stuck at state={last} after {timeout_s}s, expected one of {sorted(terminal_ok)}"
    )


def _delete_trust_and_wait(ctx, directory_id, trust_id, timeout_s=600.0, interval_s=10.0) -> None:
    ds = ctx.client("ds")
    try:
        ds.delete_trust(TrustId=trust_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityDoesNotExistException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
                return
            raise
        trusts = resp.get("Trusts", [])
        if not trusts or trusts[0]["TrustState"] == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust {trust_id} still present in DescribeTrusts after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
