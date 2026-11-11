"""visibility-directory-unavailable-during-creation-blocked."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where Directory Service cannot place domain controllers (CreateMicrosoftAD: "Failed to
# locate Availability Zone"); subnets there are never offered to it. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "visibility-directory-unavailable-during-creation-blocked"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!Test2024"
_REMOTE_DOMAIN = "remote.sim2real-example.com"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConditionalForwarder called while the directory is still Creating is rejected
    with InvalidParameterException ("... is not in Active or Impaired state"); the same
    call succeeds once DescribeDirectories reports the directory as Active."""
    ds = ctx.client("ds")
    vpc_id, subnet_pairs = _pick_vpc_and_subnet_pairs(ctx)
    name = f"{ctx.unique_name('sim2realds')}.test"
    # NOTE: Simple AD (via create_directory) is "no longer open to new customers" on real
    # AWS; create_microsoft_ad is the supported equivalent -- it still starts out in
    # Requested/Creating before reaching Active, which is what this check exercises.
    directory_id = _create_microsoft_ad_avoiding_constrained_az(ds, name, vpc_id, subnet_pairs)

    def _cleanup():
        # A directory still provisioning can refuse DeleteDirectory; retry inside the teardown window.
        deadline = time.monotonic() + 780
        while True:
            try:
                ds.delete_directory(DirectoryId=directory_id)
                return
            except ClientError as e:
                if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                    return
                if time.monotonic() >= deadline:
                    raise
            time.sleep(20)

    ctx.on_cleanup(_cleanup)

    stage_at_call_time = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0][
        "Stage"
    ]
    assert stage_at_call_time in ("Requested", "Creating"), (
        f"expected the directory to still be provisioning, got stage={stage_at_call_time}"
    )

    # Real AWS's rejection code here is racy against a propagation lag that is independent of
    # the Stage field: even after DescribeDirectories already reports Creating, the
    # conditional-forwarder subsystem can still answer EntityDoesNotExistException for a few
    # more seconds before it settles on the real, stable rejection -- InvalidParameterException
    # ("... is not in Active or Impaired state"), which holds for the rest of Creating.
    # Retry past that specific transient code (genuine eventual
    # consistency) rather than trusting Stage to have synchronized the two subsystems.
    code, message, request_id = _first_stable_error(
        lambda: ds.create_conditional_forwarder(
            DirectoryId=directory_id, RemoteDomainName=_REMOTE_DOMAIN, DnsIpAddrs=["203.0.113.5"]
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got: {code}"
    expected_message = (
        f"Could not create conditional forwarder as directory: {directory_id} is not in Active or "
        f"Impaired state. : RequestId: {request_id}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # DescribeConditionalForwarders itself requires Active/Impaired -- it is rejected with the
    # same InvalidParameterException while Creating, so it cannot serve as the independent read
    # here. Confirm absence once the directory reaches Active, before the positive control.
    _wait_directory_stage(ctx, directory_id, {"Active"}, timeout_s=2700)

    forwarders = ds.describe_conditional_forwarders(DirectoryId=directory_id)["ConditionalForwarders"]
    assert forwarders == [], "the earlier blocked create must not have left a partial conditional forwarder"

    # Positive control: the identical call succeeds once the directory is Active.
    ds.create_conditional_forwarder(
        DirectoryId=directory_id, RemoteDomainName=_REMOTE_DOMAIN, DnsIpAddrs=["203.0.113.5"]
    )
    forwarders_after = ds.describe_conditional_forwarders(DirectoryId=directory_id)["ConditionalForwarders"]
    assert any(f["RemoteDomainName"] == _REMOTE_DOMAIN for f in forwarders_after), (
        f"expected a forwarder for {_REMOTE_DOMAIN!r} once Active, got {forwarders_after!r}"
    )


def _first_stable_error(fn, max_attempts=8, interval_s=15):
    """Poll past a transient EntityDoesNotExistException (the conditional-forwarder subsystem still
    catching up to a freshly created directory) until a different, stable error code is observed;
    return its (code, message, RequestId). A call that succeeds raises."""
    last = (None, None, None)
    for _ in range(max_attempts):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
            code, message = err.get("Code"), err.get("Message") or ""
            if code != "EntityDoesNotExistException":
                return code, message, request_id
            last = (code, message, request_id)
            time.sleep(interval_s)
            continue
        raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    return last


def _pick_vpc_and_subnet_pairs(ctx):
    """Return (vpc_id, candidate_subnet_pairs) — every 2-AZ combination available, so a
    directory create that fails with "Failed to locate Availability Zone ... capacity
    constrained" (a real, observed per-account/AZ restriction, not a fidelity defect) can
    retry against a different pair instead of hard-depending on the first two AZs found."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for sn in subnets:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
        subnet_ids = list(by_az.values())
        if len(subnet_ids) >= 2:
            pairs = [
                [subnet_ids[i], subnet_ids[j]]
                for i in range(len(subnet_ids))
                for j in range(i + 1, len(subnet_ids))
            ]
            return vpc["VpcId"], pairs
    raise AssertionError("no VPC with subnets in >=2 availability zones to provision a DS directory")


def _create_microsoft_ad_avoiding_constrained_az(ds, name, vpc_id, subnet_pairs):
    last_exc = None
    for pair in subnet_pairs:
        try:
            return ds.create_microsoft_ad(
                Name=name,
                Password=_PASSWORD,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": pair},
                Edition="Standard",
                Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
            )["DirectoryId"]
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            if "capacity constrained" in message or "Failed to locate Availability Zone" in message:
                last_exc = exc
                continue
            raise
    raise last_exc


def _wait_directory_stage(ctx, directory_id, target_stages, timeout_s=1500, interval_s=20):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory entered terminal failure stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(f"directory did not reach {target_stages} within {timeout_s}s (last={stage})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
