"""disable-sso-authentication-failed-rejected."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-sso-authentication-failed-rejected"
GROUP = "overly-permissive"
SERVICES = ["ds"]

# Unique to this check: a run deletes the directory it creates, so no other check may find it.
_SHARED_AD_NAME = "sim2real-ds-ssodisable-std.example.com"
_SHARED_AD_PASSWORD = "Sim2Real-SharedAD-Pw924!"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableSso and DisableSso flip a live directory's SsoEnabled flag, and DisableSso on a well-formed
    nonexistent DirectoryId fails with EntityDoesNotExistException and "Directory: '<id>' does not
    exist." while the real directory's flag stays False."""
    directory_id = _get_or_create_shared_directory(ctx, _SHARED_AD_NAME, "Standard")

    ds = ctx.client("ds")
    _ensure_alias(ctx, ds, directory_id)

    def _sso_enabled() -> bool:
        return ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["SsoEnabled"]

    if _sso_enabled():
        _call_with_retry(lambda: ds.disable_sso(DirectoryId=directory_id))
        _wait_for_sso_state(ctx, directory_id, False)
    state = _sso_enabled()
    assert state is False, f"expected SsoEnabled False after DisableSso, got {state}"

    # Positive control: EnableSso actually flips the directory's SsoEnabled flag.
    _call_with_retry(lambda: ds.enable_sso(DirectoryId=directory_id))
    _wait_for_sso_state(ctx, directory_id, True)
    state = _sso_enabled()
    assert state is True, f"expected SsoEnabled True after EnableSso, got {state}"

    # Positive control: DisableSso flips it back.
    _call_with_retry(lambda: ds.disable_sso(DirectoryId=directory_id))
    _wait_for_sso_state(ctx, directory_id, False)
    state = _sso_enabled()
    assert state is False, f"expected SsoEnabled False after DisableSso, got {state}"

    # Negative: DisableSso against a well-formed but nonexistent DirectoryId is rejected.
    bogus_directory_id = "d-0000000000"
    code, message, request_id = _error(lambda: ds.disable_sso(DirectoryId=bogus_directory_id))
    assert code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException disabling SSO on a nonexistent directory, got {code}"
    )
    expected_message = f"Directory: '{bogus_directory_id}' does not exist. : RequestId: {request_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the real directory's SsoEnabled state is unaffected by the failed call
    # against the unrelated bogus DirectoryId.
    state = _sso_enabled()
    assert state is False, f"expected the real directory's SsoEnabled to remain False, got {state}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


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


def _error(fn, timeout_s=60, interval_s=6):
    """Call fn(); return the (Code, Message, RequestId) of the ClientError it raises, retrying
    transient refusals. A success raises."""
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
            f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
        )


def _call_with_retry(fn, timeout_s=60, interval_s=6):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if _is_transient(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _ensure_alias(ctx, ds, directory_id) -> None:
    """EnableSso requires the directory to have a registered alias/access URL first
    ("An alias is required before enabling SSO"). An alias can only be set ONCE per
    directory and is globally unique, so this only creates one if the directory does not
    already have one (e.g. from a previous run reusing this shared fixture)."""
    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    if desc.get("Alias") and desc["Alias"] != directory_id:
        return
    alias = ctx.unique_name("sim2real-behav-ds-b2-alias-").lower()
    try:
        _call_with_retry(lambda: ds.create_alias(DirectoryId=directory_id, Alias=alias))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityAlreadyExistsException":
            raise
        # Lost a race with a concurrently-running check that just set the alias -- fine, an
        # alias exists either way.


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
    """The DirectoryId of the Active Managed Microsoft AD named for this check, created on first use
    or adopted from an earlier run of this check; the run deletes it (and any network it created)."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    existing = _find_directory_by_name(ds, name)
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
                ctx.on_cleanup(lambda sid=subnet["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid))
                subnet_ids.append(subnet["SubnetId"])
            resp = ds.create_microsoft_ad(
                Name=name,
                Password=_SHARED_AD_PASSWORD,
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
        except ClientError:
            # Lost the create race with a concurrently running check (duplicate
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

    # The name is unique to this check, so the directory is this run's to remove, whether it was
    # created here or is a leftover of an earlier run of this check.
    ctx.on_cleanup(lambda did=directory_id: _safe(lambda: _delete_directory_and_wait(ds, did)))
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


def _wait_for_sso_state(ctx, directory_id, expected: bool, timeout_s=90, interval_s=5):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["SsoEnabled"]
        if state == expected:
            return
        time.sleep(interval_s)
    raise AssertionError(f"SsoEnabled never reached {expected} within {timeout_s}s (last={state})")


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so a network
# delete waits (bounded, within the cleanup budget) for them and retries DependencyViolation, then
# raises naming the ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    network. DeleteDirectory is retried while the directory is still being created or is still
    shared with another account. Teardown-only: run() never calls this."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if "shared" in e.response["Error"].get("Message", "").lower():
                try:
                    shared = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
                except ClientError:
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in (
                            "DirectoryNotSharedException",
                            "EntityDoesNotExistException",
                        ):
                            raise
            elif code not in ("ClientException", "InvalidParameterException"):
                raise
            if time.monotonic() >= deadline:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
