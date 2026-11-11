"""trust-lifecycle-create-verify-delete."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "trust-lifecycle-create-verify-delete"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Two-Way trust to an unresolvable remote domain settles at Failed with AWS's internal-error reason
    without any VerifyTrust; VerifyTrust on it then fails with InvalidParameterException, and after
    DeleteTrust both DescribeTrusts and a second delete fail with "Trust: <id> does not exist"."""
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    ctx.on_cleanup(lambda: _cleanup_delete_directory(ctx, directory_id))
    _wait_for_directory_stage(ctx, ds, directory_id, {"Active", "Failed"}, timeout_s=2700)
    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc["Stage"] == "Active", f"expected the directory to settle Active before trust work, got {desc['Stage']!r}"

    trust_resp = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName="unreachable.sim2real.invalid",
        TrustPassword="Sim2Real-Trust-Passw0rd!",
        TrustDirection="Two-Way",
        ConditionalForwarderIpAddrs=["203.0.113.5"],
    )
    trust_id = trust_resp["TrustId"]

    def _cleanup_trust():
        try:
            ds.delete_trust(TrustId=trust_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup_trust)

    # The trust-establishment handshake against an unreachable remote domain fails on its own and
    # settles at Failed, so no VerifyTrust call is needed to reach a terminal state. VerifyFailed and
    # Verified also end the wait; the assertion below is exact either way.
    settled = _wait_for_trust_state(
        ctx, ds, directory_id, trust_id, {"Failed", "VerifyFailed", "Verified"}, timeout_s=600
    )
    assert settled["TrustState"] == "Failed", (
        f"expected a trust to an unreachable remote domain to fail its own creation handshake "
        f"and settle at 'Failed', got {settled['TrustState']!r}"
    )
    expected_reason = (
        "An internal service error has been encountered while creating the trust. Please retry the operation."
    )
    assert settled.get("TrustStateReason") == expected_reason, (
        f"expected TrustStateReason {expected_reason!r} on the Failed trust, got {settled!r}"
    )

    # _error raises if VerifyTrust succeeds: a terminal trust must be refused.
    verify_code, verify_message, verify_rid = _error(lambda: ds.verify_trust(TrustId=trust_id))
    assert verify_code == "InvalidParameterException", f"unexpected VerifyTrust refusal code {verify_code!r}"
    expected_verify = f"Cannot verify trust in state: Failed : RequestId: {verify_rid}"
    assert verify_message == expected_verify, f"expected message {expected_verify!r}, got {verify_message!r}"

    ds.delete_trust(TrustId=trust_id)
    code, message, request_id = _wait_for_describe_trust_refused(ds, directory_id, trust_id, timeout_s=900)
    assert code == "EntityDoesNotExistException", f"expected trust to 404 after delete, got code={code!r}"
    expected = f"Trust: {trust_id} does not exist : RequestId: {request_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    redelete_code, redelete_message, redelete_rid = _error(lambda: ds.delete_trust(TrustId=trust_id))
    assert redelete_code == "EntityDoesNotExistException", (
        f"a second DeleteTrust on the already-deleted trust must also refuse with "
        f"EntityDoesNotExistException, got code={redelete_code!r}"
    )
    expected_redelete = f"Trust: {trust_id} does not exist : RequestId: {redelete_rid}"
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it raises.
    ds echoes the refused call's RequestId in its message. An unexpected SUCCESS raises
    instead of returning a falsy sentinel that would read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        request_id = (e.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_describe_trust_refused(ds, directory_id: str, trust_id: str, timeout_s: float, interval_s: float = 15.0):
    """Poll DescribeTrusts on a deleted trust until it is refused; return that refusal's
    (code, message, RequestId). Raises if the trust is still listed when the window closes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            trusts = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"]
        except ClientError as e:
            err = e.response.get("Error", {})
            request_id = (e.response.get("ResponseMetadata") or {}).get("RequestId")
            return err.get("Code"), err.get("Message") or "", request_id
        if time.monotonic() >= deadline:
            raise AssertionError(f"trust {trust_id} still described {timeout_s}s after DeleteTrust: {trusts!r}")
        time.sleep(interval_s)


def _default_vpc_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in the region to host the directory's network interfaces")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in >=2 availability zones, required by CreateMicrosoftAD")
    return vpc_id, by_az


def _create_microsoft_ad(ctx) -> str:
    ds = ctx.client("ds")
    vpc_id, by_az = _default_vpc_az_subnets(ctx)

    # Some availability zones are transiently capacity-constrained for Managed Microsoft AD
    # and CreateMicrosoftAD refuses with a ClientException naming the offending AZ/subnet --
    # try every distinct AZ pair the default VPC offers before giving up, so one constrained
    # AZ in a >2-AZ VPC does not fail a check that has nothing to do with AZ capacity.
    az_pairs = list(itertools.combinations(sorted(by_az), 2))
    last_error: ClientError | None = None
    for az_a, az_b in az_pairs:
        subnet_ids = [by_az[az_a], by_az[az_b]]
        name = ctx.unique_name("sim2realds") + ".test"
        try:
            resp = ds.create_microsoft_ad(
                Name=name,
                Password="Sim2Real-Test-Passw0rd!",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
                Edition="Standard",
                Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "ClientException" or "capacity constrained" not in str(e):
                raise
            last_error = e
            continue
        return resp["DirectoryId"]
    raise AssertionError(
        f"CreateMicrosoftAD refused every AZ pair from {sorted(by_az)!r} as capacity constrained: {last_error}"
    )


def _cleanup_delete_directory(ctx, directory_id: str) -> None:
    ds = ctx.client("ds")
    try:
        _delete_directory_and_wait(ds, directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _wait_for_directory_stage(ctx, ds, directory_id: str, targets: set[str], timeout_s: float = 2700.0, interval_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage in targets:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage {last_stage!r} after {timeout_s}s")


def _wait_for_trust_state(
    ctx, ds, directory_id: str, trust_id: str, targets: set[str], timeout_s: float = 900.0, interval_s: float = 15.0
):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        trusts = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"]
        if trusts:
            last_state = trusts[0]["TrustState"]
            if last_state in targets:
                return trusts[0]
        time.sleep(interval_s)
    raise AssertionError(f"trust {trust_id} stuck at state {last_state!r} after {timeout_s}s")


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
