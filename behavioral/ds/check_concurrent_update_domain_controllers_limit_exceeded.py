"""concurrent-update-domain-controllers-limit-exceeded."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "concurrent-update-domain-controllers-limit-exceeded"
GROUP = "concurrency"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateNumberOfDomainControllers to 21 is refused with DomainControllerLimitExceededException alone,
    and refused (over the limit or busy) when raced with an in-limit update, which still lands: the
    controller count grows by one and never exceeds 20. All refusals carry AWS's exact messages."""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _default_vpc_and_two_az_subnets(ctx)
    name = ctx.unique_name("sim2real-ds-dcrace").replace("_", "-").rstrip("-") + ".test"

    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password="TestPassw0rd!23",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_directory_and_wait(ds, directory_id)))
    _wait_directory_active(ds, directory_id)

    initial_count = len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"])

    last_update_error: dict = {}

    def _update(desired_number):
        try:
            ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=desired_number)
            return None
        except ClientError as e:
            last_update_error["message"] = e.response["Error"].get("Message")
            last_update_error["request_id"] = e.response["ResponseMetadata"]["RequestId"]
            return e.response["Error"]["Code"]

    def _rejected_update(desired_number):
        """(code, message, request id) of an update AWS refuses; an unexpected success raises."""
        try:
            result = ds.update_number_of_domain_controllers(DirectoryId=directory_id, DesiredNumber=desired_number)
        except ClientError as e:
            return (
                e.response["Error"]["Code"],
                e.response["Error"].get("Message"),
                e.response["ResponseMetadata"]["RequestId"],
            )
        raise AssertionError(f"expected DesiredNumber={desired_number} to be rejected, but it succeeded: {result!r}")

    def _limit_message(request_id):
        return (
            "Domain controllers limit exceeded. A maximum of 20 domain controllers may be requested. "
            f": RequestId: {request_id}"
        )

    def _busy_message(request_id):
        return (
            f"The directory is currently unavailable for updates. The directory {directory_id} is under "
            f"maintenance. Please retry the operation after a few minutes. : RequestId: {request_id}"
        )

    # Solo negative control on an otherwise-idle directory: proves value validation itself
    # rejects the over-limit number, uncontaminated by any concurrency-busy signal.
    solo_invalid_code, solo_message, solo_request_id = _rejected_update(21)  # exceeds the documented max of 20
    assert solo_invalid_code == "DomainControllerLimitExceededException", (
        f"expected a solo (non-concurrent) over-limit update to be rejected with "
        f"DomainControllerLimitExceededException, got {solo_invalid_code!r}"
    )
    expected_message = _limit_message(solo_request_id)
    assert solo_message == expected_message, f"expected {expected_message!r}, got {solo_message!r}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        future_valid = pool.submit(_update, initial_count + 1)  # well within the 20-controller-per-directory limit
        future_invalid = pool.submit(_rejected_update, 21)  # exceeds the documented max of 20
        valid_code = future_valid.result()
        invalid_code, invalid_message, invalid_request_id = future_invalid.result()

    # The over-limit request must never be silently accepted: it is rejected either for its own
    # value (DomainControllerLimitExceededException) or, if it loses the race to the concurrent
    # in-limit mutation, as busy (DirectoryUnavailableException) -- both are correct, since either
    # way the over-limit mutation never lands.
    assert invalid_code in ("DomainControllerLimitExceededException", "DirectoryUnavailableException"), (
        f"expected the over-limit concurrent update to be rejected (for its own value, or for "
        f"losing the race to the concurrent in-limit mutation), got {invalid_code!r}"
    )
    if invalid_code == "DomainControllerLimitExceededException":
        expected_message = _limit_message(invalid_request_id)
    else:
        expected_message = _busy_message(invalid_request_id)
    assert invalid_message == expected_message, f"expected {expected_message!r}, got {invalid_message!r}"

    # The in-limit request must not be starved by the race: succeed outright, or -- if IT lost
    # the race and was the one told the directory was busy -- succeed on a bounded retry once the
    # directory frees up again.
    if valid_code is not None:
        assert valid_code == "DirectoryUnavailableException", (
            f"expected the in-limit concurrent update to succeed or lose the race as busy, got {valid_code!r}"
        )
        expected_message = _busy_message(last_update_error["request_id"])
        assert last_update_error["message"] == expected_message, (
            f"expected {expected_message!r}, got {last_update_error['message']!r}"
        )
        valid_code = _update_with_retry(_update, initial_count + 1)
    assert valid_code is None, f"expected the within-limit update to eventually succeed, got {valid_code}"

    # effect present: the in-limit request actually grew the controller fleet -- proving the
    # concurrent submission did not also silently swallow the valid request. We only wait for the
    # new domain controller RECORD to appear, not for it to finish becoming Active, since that
    # final transition can take far longer than this check's budget.
    def _grew():
        return len(ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"]) == initial_count + 1

    assert _poll_until(_grew, timeout_s=120, interval_s=10), (
        f"expected DescribeDomainControllers to list {initial_count + 1} controllers after the "
        f"accepted update, last count="
        f"{len(ds.describe_domain_controllers(DirectoryId=directory_id)['DomainControllers'])}"
    )

    # effect absent: neither over-limit request pushed the controller count near 21
    controllers = ds.describe_domain_controllers(DirectoryId=directory_id)["DomainControllers"]
    assert len(controllers) <= 20, f"expected controller count to remain <=20 (documented max), got {len(controllers)}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _poll_until(predicate, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return predicate()


def _update_with_retry(update_fn, desired_number, timeout_s=180.0, interval_s=15.0):
    """Retries `update_fn(desired_number)` while the directory reports busy; returns the first
    non-busy outcome (None on success, or the terminal error code)."""
    deadline = time.monotonic() + timeout_s
    while True:
        code = update_fn(desired_number)
        if code != "DirectoryUnavailableException" or time.monotonic() >= deadline:
            return code
        time.sleep(interval_s)


def _default_vpc_and_two_az_subnets(ctx):

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
    subnet_ids = list(by_az.values())[:2]
    return vpc_id, subnet_ids


def _wait_directory_active(ds, directory_id, timeout_s=2700.0, interval_s=30.0):
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
