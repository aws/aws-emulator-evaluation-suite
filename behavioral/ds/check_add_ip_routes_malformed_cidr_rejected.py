"""add-ip-routes-malformed-cidr-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "add-ip-routes-malformed-cidr-rejected"
GROUP = "negative-classes"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddIpRoutes with a syntactically malformed CIDR block is rejected with
    ValidationException before any route is persisted; a well-formed CIDR in the same call
    batch is also not persisted (all-or-nothing), and a subsequent valid call succeeds.
    """
    directory_id = _create_microsoft_ad_directory(ctx)
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    ds = ctx.client("ds")
    malformed_cidr = "10.0.0.0"  # missing required /prefix

    # Break exactly one thing: submit a malformed CIDR.
    code, message = _error_code_and_message(
        lambda: ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": malformed_cidr}])
    )
    assert code == "ValidationException", f"expected ValidationException for a malformed CIDR, got {code}"
    expected_message = _cidr_validation_message(malformed_cidr, 1)
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: no route was persisted for the malformed request.
    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    assert routes == [], f"expected no persisted routes after a rejected AddIpRoutes call, found {routes}"

    # Same-call batch: a malformed CIDR alongside a well-formed one in one AddIpRoutes
    # call is rejected as a whole -- the well-formed entry is not persisted either.
    batch_cidr = "198.51.100.0/24"
    batch_code, batch_message = _error_code_and_message(
        lambda: ds.add_ip_routes(
            DirectoryId=directory_id,
            IpRoutes=[{"CidrIp": malformed_cidr}, {"CidrIp": batch_cidr}],
        )
    )
    assert batch_code == "ValidationException", (
        f"expected a mixed batch containing a malformed CIDR to be rejected as a whole, got {batch_code}"
    )
    assert batch_message == expected_message, f"expected {expected_message!r}, got {batch_message!r}"
    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    assert routes == [], (
        f"expected no persisted routes after a mixed-batch rejected AddIpRoutes call, found {routes}"
    )

    # Positive control: a well-formed CIDR on the same directory is accepted and appears
    # in ListIpRoutes.
    valid_cidr = "203.0.113.0/24"
    ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": valid_cidr}])
    ctx.on_cleanup(lambda: _safe_remove_route(ctx, directory_id, valid_cidr))
    added_status = _wait_for_route_status(ctx, directory_id, valid_cidr, {"Added"})
    assert added_status == "Added", f"expected the well-formed CIDR to reach Added, got {added_status}"


_CIDR_IP_PATTERN = (
    r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
    r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-9]|[1-2][0-9]|3[0-2]))$"
)


def _cidr_validation_message(cidr, member_index):
    return (
        f"1 validation error detected: Value '{cidr}' at 'ipRoutes.{member_index}.member.cidrIp' "
        f"failed to satisfy constraint: Member must satisfy regular expression pattern: {_CIDR_IP_PATTERN}"
    )


def _error_code_and_message(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn() raises; raise if it succeeds."""
    try:
        resp = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


def _default_vpc_two_azs(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("need subnets in at least 2 distinct AZs to create a test directory")
    azs = sorted(by_az)
    return vpc_id, [by_az[azs[0]], by_az[azs[1]]]


def _create_microsoft_ad_directory(ctx, password="Sim2Real-TestPW1"):
    # Simple AD (CreateDirectory) is "no longer open to new customers" on real AWS;
    # CreateMicrosoftAD is the supported equivalent with the same Creating -> Active
    # lifecycle this check needs to reach AddIpRoutes.
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _default_vpc_two_azs(ctx)
    name = ctx.unique_name("sim2real-ds-") + ".test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=password,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ctx, directory_id))
    return directory_id


def _safe_delete_directory(ctx, directory_id):
    """Delete the directory and wait until it is gone. A refused DeleteDirectory is ignored; a
    directory still present after the wait raises, since its ENIs would keep the shared network
    from being deleted."""
    ds = ctx.client("ds")
    try:
        _delete_directory_and_wait(ds, directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _safe_remove_route(ctx, directory_id, cidr):
    ds = ctx.client("ds")
    try:
        ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr])
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


def _wait_for_route_status(ctx, directory_id, cidr, target_statuses, timeout_s=180, interval_s=10):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        matching = [r for r in routes if r["CidrIp"] == cidr]
        last = matching[0]["IpRouteStatusMsg"] if matching else None
        if last in target_statuses:
            return last
        if last == "AddFailed" and "AddFailed" not in target_statuses:
            raise AssertionError(f"route {cidr} failed to add")
        time.sleep(interval_s)
    raise AssertionError(f"route {cidr} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _delete_directory_and_wait(ds, directory_id, timeout_s=1500.0, interval_s=30.0):
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
