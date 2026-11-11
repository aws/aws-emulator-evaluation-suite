"""create-trust-duplicate-name-rejected."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-trust-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_AD_NAME = "sim2dsb7a2c4e1.example.com"
_SHARED_AD_PASSWORD = "Sim2Real-SharedAD-Pw924!"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateTrust for the same RemoteDomainName on an active Managed Microsoft AD
    directory is rejected with EntityAlreadyExistsException, and the directory still has
    exactly one trust for that domain (the original)."""
    directory_id = _get_or_create_shared_directory(ctx, _SHARED_AD_NAME, "Standard")

    ds = ctx.client("ds")
    remote_domain = f"{ctx.unique_name('corp-')}.example.com".lower()
    trust_password = "Sim2Real-Trust-Pw924!"

    # Positive control: the first trust creation for this domain succeeds.
    resp = _call_with_retry(
        lambda: ds.create_trust(
            DirectoryId=directory_id,
            RemoteDomainName=remote_domain,
            TrustPassword=trust_password,
            TrustDirection="One-Way: Outgoing",
        )
    )
    trust_id = resp["TrustId"]
    ctx.on_cleanup(lambda: _safe(lambda: ds.delete_trust(TrustId=trust_id)))

    trusts = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
    matching = [t for t in trusts if t["RemoteDomainName"] == remote_domain]
    assert len(matching) == 1, (
        f"expected exactly 1 trust for {remote_domain} right after the positive-control "
        f"create, found {len(matching)}"
    )
    assert matching[0]["TrustId"] == trust_id, (
        f"expected the positive-control trust id {trust_id!r}, found "
        f"{matching[0]['TrustId']!r}"
    )

    # Negative: a second CreateTrust for the same RemoteDomainName is rejected.
    code, message, request_id = _error(
        lambda: ds.create_trust(
            DirectoryId=directory_id,
            RemoteDomainName=remote_domain,
            TrustPassword=trust_password,
            TrustDirection="One-Way: Outgoing",
        )
    )
    assert code == "EntityAlreadyExistsException", (
        f"expected EntityAlreadyExistsException for a duplicate RemoteDomainName on an "
        f"active directory, got {code!r}"
    )
    expected_message = (
        f"Trust already exists for directory: {directory_id} and remote domain: "
        f"{remote_domain}. : RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: still exactly one trust for that domain, unchanged TrustId.
    trusts_after = ds.describe_trusts(DirectoryId=directory_id)["Trusts"]
    matching_after = [t for t in trusts_after if t["RemoteDomainName"] == remote_domain]
    assert len(matching_after) == 1, (
        f"expected exactly 1 trust for {remote_domain} after the rejected duplicate "
        f"create, found {len(matching_after)}"
    )
    assert matching_after[0]["TrustId"] == trust_id, (
        f"expected the original trust id {trust_id!r} to be unchanged by the rejected "
        f"duplicate create, found {matching_after[0]['TrustId']!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _is_transient(exc: ClientError) -> bool:
    err = exc.response.get("Error", {})
    code = err.get("Code", "")
    msg = err.get("Message", "").lower()
    if code in ("DirectoryUnavailableException", "VpcLimitExceeded"):
        return True
    if code == "ClientException" and any(
        m in msg for m in ("maintenance", "already in progress", "please wait", "try again")
    ):
        return True
    return False


def _error(fn, timeout_s=150, interval_s=8):
    """Call fn(); return its botocore (Code, Message, RequestId). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            if _is_transient(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            err = e.response["Error"]
            request_id = e.response.get("ResponseMetadata", {}).get("RequestId")
            return err["Code"], err.get("Message"), request_id
        raise AssertionError(
            f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
        )


def _call_with_retry(fn, timeout_s=150, interval_s=8):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if _is_transient(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _find_directory_by_name(ds, name):
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = ds.describe_directories(**kwargs)
        for d in resp.get("DirectoryDescriptions", []):
            if d.get("Name") == name and d.get("Stage") != "Deleted":
                return d
        token = resp.get("NextToken")
        if not token:
            return None


def _get_or_create_shared_directory(ctx, name, edition, timeout_s=2700):
    """Idempotently returns the DirectoryId of an Active Managed Microsoft AD directory with
    this check's own name. The directory, and any network created for it, is deleted in
    cleanup, whether created here or left over from an earlier run of this check."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    existing = _find_directory_by_name(ds, name)
    if existing is not None:
        ctx.on_cleanup(lambda did=existing["DirectoryId"]: _delete_directory_and_wait(ds, did))
    if existing is not None and existing.get("Stage") == "Failed":
        raise AssertionError(
            f"shared fixture directory {existing['DirectoryId']!r} ({name}) is in Failed "
            "stage; delete it manually before re-running this batch"
        )
    directory_id = existing["DirectoryId"] if existing is not None else None
    if directory_id is None:
        try:
            ec2 = ctx.client("ec2")
            octet = random.randint(0, 200)
            vpc = ec2.create_vpc(
                CidrBlock=f"10.{octet}.0.0/23",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ds-shared-vpc-")}],
                }],
            )["Vpc"]
            vpc_id = vpc["VpcId"]
            # Registered first, so it runs after the subnets and the directory are gone (LIFO).
            ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
            azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
            subnet_ids = []
            for i, az in enumerate(azs):
                subnet = ec2.create_subnet(
                    VpcId=vpc_id,
                    CidrBlock=f"10.{octet}.{i}.0/24",
                    AvailabilityZone=az,
                    TagSpecifications=[{
                        "ResourceType": "subnet",
                        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-ds-shared-subnet-")}],
                    }],
                )["Subnet"]
                subnet_ids.append(subnet["SubnetId"])
                ctx.on_cleanup(lambda sid=subnet["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid))
            resp = ds.create_microsoft_ad(
                Name=name,
                Password=_SHARED_AD_PASSWORD,
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
            ctx.on_cleanup(lambda did=directory_id: _delete_directory_and_wait(ds, did))
        except ClientError:
            # Lost the create race with a concurrently-running check in this batch (duplicate
            # name, VPC/directory quota momentarily exhausted by a sibling attempt, etc.) --
            # fall back to waiting for whichever check wins the race to finish creating it.
            directory_id = None
            while directory_id is None and time.monotonic() < deadline:
                time.sleep(2)
                found = _find_directory_by_name(ds, name)
                if found is not None:
                    directory_id = found["DirectoryId"]
            if directory_id is None:
                raise

    remaining = max(30.0, deadline - time.monotonic())
    return _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"}, timeout_s=remaining)["DirectoryId"]


def _wait_directory_stage(ctx, directory_id, target_stages, failure_stages, timeout_s=260, interval_s=10):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in failure_stages:
            raise AssertionError(f"directory {directory_id} entered {stage}: {desc.get('StageReason')}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={desc})"
    )


def _delete_directory_and_wait(ds, directory_id, timeout_s=1800.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    VPC. DeleteDirectory is retried while the directory is still being created."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if code not in ("ClientException", "InvalidParameterException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(interval_s)


def _delete_net(ec2, op, timeout_s=900.0, **ident):
    """Delete a VPC or subnet this check created, retrying DependencyViolation while the deleted
    directory's network interfaces are still being released."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            getattr(ec2, op)(**ident)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
