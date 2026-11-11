"""enable-sso-missing-permission-denied."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "enable-sso-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableSso with a UserName/Password that does not authenticate against the directory fails
    with AuthenticationFailedException, while the same call with the directory's managed
    credentials succeeds (positive control); an alias is created first so only credentials differ."""
    ds = ctx.client("ds")
    vpc_id, az_subnets = _default_vpc_az_subnets(ctx)
    name = ctx.unique_name("sim2real-ds-sso").replace("_", "-").rstrip("-") + ".test"

    directory_id = _create_microsoft_ad_avoiding_unsupported_az(
        ds, vpc_id, az_subnets, name, "TestPassw0rd!23"
    )
    ctx.on_cleanup(lambda: _safe(lambda: ds.delete_directory(DirectoryId=directory_id)))
    _wait_directory_active(ds, directory_id)

    alias = ctx.unique_name("sim2real-ds-sso-alias").replace("_", "-").rstrip("-").lower()
    ds.create_alias(DirectoryId=directory_id, Alias=alias)

    # The directory's own Admin with a wrong password: a user name the directory does not know
    # is refused earlier, with EntityDoesNotExistException, before any credential check.
    code = _error_code(
        lambda: ds.enable_sso(
            DirectoryId=directory_id, UserName="Admin", Password="Wr0ng-Passw0rd!"
        )
    )
    assert code == "AuthenticationFailedException", f"expected AuthenticationFailedException, got {code}"

    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc.get("SsoEnabled") is False, "SSO must not have been enabled by the failed call"

    # positive control: without an (incorrect) override, EnableSso uses the directory's
    # own managed service-account credentials and succeeds
    ds.enable_sso(DirectoryId=directory_id)
    desc2 = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc2.get("SsoEnabled") is True, "SSO must be enabled once the bogus override is removed"


# ===== helpers =====
def _error_code(fn):
    """The error code of the refusal fn() must raise; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _default_vpc_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            f"VPC {vpc_id} does not have subnets in >=2 distinct AZs required to provision a directory"
        )
    return vpc_id, by_az


def _create_microsoft_ad_avoiding_unsupported_az(ds, vpc_id, az_subnets, name, password):
    """DS does not support every AZ in a region for directory placement (some are capacity
    constrained); real AWS rejects those with a ClientException naming the specific subnet.
    Try every AZ pair in the VPC in order until one is accepted."""
    from botocore.exceptions import ClientError

    azs = list(az_subnets)
    last_err = None
    for i in range(len(azs)):
        for j in range(i + 1, len(azs)):
            subnet_ids = [az_subnets[azs[i]], az_subnets[azs[j]]]
            try:
                return ds.create_microsoft_ad(
                    Name=name,
                    Password=password,
                    Edition="Standard",
                    VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
                    Tags=[{"Key": "Name", "Value": name}],
                )["DirectoryId"]
            except ClientError as e:
                err = e.response["Error"]
                if err["Code"] == "ClientException" and "Failed to locate Availability Zone" in err.get(
                    "Message", ""
                ):
                    last_err = e
                    continue
                raise
    raise AssertionError(f"no AZ pair in VPC {vpc_id} is accepted for a DS directory (last error: {last_err})")


def _wait_directory_active(ds, directory_id, timeout_s=3600.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage == "Active":
            return desc
        if last_stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach Active within {timeout_s}s (last={last_stage})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
