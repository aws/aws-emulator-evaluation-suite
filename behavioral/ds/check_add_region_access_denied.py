"""add-region-access-denied."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-region-access-denied"
GROUP = "overly-permissive"
SERVICES = ["ds"]

_SHARED_AD_NAME = "sim2real-behav-ds-b2-shared-ent.example.com"
_SHARED_AD_PASSWORD = "Sim2Real-SharedAD-Pw924!"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller whose IAM policy denies ds:AddRegion gets AccessDeniedException, while an
    unrestricted caller reaches the DS business logic and gets UnsupportedOperationException
    instead, proving the block is the missing permission and not another rejection."""
    directory_id = _get_or_create_shared_directory(ctx, _SHARED_AD_NAME, "Enterprise", timeout_s=2500)

    ds = ctx.client("ds")
    home_vpc_settings = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0][
        "VpcSettings"
    ]

    denied_ds = _denied_ds_client(ctx, ["ds:AddRegion"])

    add_region_kwargs = dict(
        DirectoryId=directory_id,
        RegionName=ctx.region,
        VPCSettings={"VpcId": home_vpc_settings["VpcId"], "SubnetIds": home_vpc_settings["SubnetIds"]},
    )

    # Negative: the IAM-denied identity is blocked before reaching DS business logic. The Deny
    # replicates across IAM backends on its own schedule, so this is a bounded poll on
    # AccessDeniedException becoming the observed answer, not a single check after a guessed
    # propagation delay -- an UNEXPECTED_SUCCESS while the Deny is still propagating keeps
    # polling, but the identical outcome after the deadline is the real, reportable failure.
    _poll(
        lambda: _error_code(lambda: denied_ds.add_region(**add_region_kwargs)),
        lambda c: c == "AccessDeniedException",
        timeout_s=90,
        interval_s=5,
        description="the ds:AddRegion explicit Deny becomes effective for the restricted identity",
    )

    # Positive control: an unrestricted identity performing the identical call reaches DS
    # business logic and is rejected there instead (AddRegion targeting the directory's own
    # home Region), never returning AccessDeniedException. AddRegion's documentation names
    # DirectoryAlreadyInRegionException for this exact case, but AWS answers
    # UnsupportedOperationException, which this asserts.
    allowed_code = _error_code(lambda: ds.add_region(**add_region_kwargs), timeout_s=150)
    assert allowed_code == "UnsupportedOperationException", (
        f"expected the unrestricted identity to reach DS business logic and be rejected with "
        f"UnsupportedOperationException (AddRegion targeting the home Region), got {allowed_code!r}"
    )

    # Effect absent in both cases: no additional region was ever added.
    regions = ds.describe_regions(DirectoryId=directory_id)["RegionsDescription"]
    assert len(regions) == 1, f"expected exactly the home Region, found {regions!r}"
    assert regions[0]["RegionName"] == ctx.region, (
        f"expected the sole region entry to be the home Region {ctx.region!r}, got {regions[0]!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
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


def _error_code(fn, timeout_s=60, interval_s=6):
    """The observed botocore error code, or the non-error sentinel "UNEXPECTED_SUCCESS" (never a
    falsy value) if fn() raised nothing -- so an over-permissive target that lets a call through
    always shows up as a plain string mismatch against the expected error code, never as a match."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return "UNEXPECTED_SUCCESS"
        except ClientError as e:
            if _is_transient(e) and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return e.response["Error"]["Code"]


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


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


def _get_or_create_shared_directory(ctx, name, edition, timeout_s=200):
    """Idempotently returns the DirectoryId of an Active shared Managed Microsoft AD fixture.
    Real provisioning takes real minutes on AWS, so a check that just needs *an* Active
    directory reuses an existing fixture instead of paying that cost once per check.
    The call that creates the fixture registers its teardown (directory, then subnets and VPC)."""
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
                subnet_ids.append(subnet["SubnetId"])
                ctx.on_cleanup(lambda sid=subnet["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid))
            resp = ds.create_microsoft_ad(
                Name=name,
                Password=_SHARED_AD_PASSWORD,
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
            )
            directory_id = resp["DirectoryId"]
            ctx.on_cleanup(lambda d=directory_id: _delete_directory_and_wait(ds, d))
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


def _denied_ds_client(ctx, denied_actions):
    """Create an IAM role that is allowed everything except `denied_actions`, assume it, and
    return a `ds` client using those temporary credentials pointed at the same endpoint/region
    the harness's own `ds` client uses (so this works against both real AWS and an emulator)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-ds-deny-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": denied_actions, "Resource": "*"},
        ],
    }
    policy_name = "deny-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # IAM role/policy propagation is eventually consistent; retry the assume-role for a bit.
    deadline = time.monotonic() + 60
    creds = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-ds")["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(5)
    if creds is None:
        raise AssertionError(f"could not assume role {role_arn}: {last_exc}")

    # Deny propagation, if any is still outstanding, is waited out by the caller's bounded poll
    # on the negative assertion itself -- not by a fixed sleep here.

    return ctx.client(
        "ds",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


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


def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=2.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""
    from botocore.exceptions import ClientError

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
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "DirectoryDoesNotExistException",
                        "EntityDoesNotExistException",
                    ):
                        raise
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in (
                            "DirectoryDoesNotExistException",
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
