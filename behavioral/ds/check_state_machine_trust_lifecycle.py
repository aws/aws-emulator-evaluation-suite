"""state-machine-trust-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "state-machine-trust-lifecycle"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrust to an unreachable remote domain is accepted into a trust record that DS then
    drives asynchronously from Creating straight to a terminal Failed state, and DeleteTrust
    removes it from DescribeTrusts."""
    # Managed Microsoft AD directory creation takes tens of minutes on real AWS, and trusts
    # only exist on that directory type.
    directory_id = _create_microsoft_ad(ctx)
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    ds = ctx.client("ds")
    remote_domain = ctx.unique_name("sim2real-trust-").replace("_", "-") + ".test"
    trust_id = ds.create_trust(
        DirectoryId=directory_id,
        RemoteDomainName=remote_domain,
        TrustPassword="Sim2Real-TestPW1",
        TrustDirection="One-Way: Outgoing",
    )["TrustId"]
    ctx.on_cleanup(lambda: _safe_delete_trust(ctx, trust_id))

    observed: list[str] = []
    final_state = _wait_for_trust_state(ctx, directory_id, trust_id, {"Failed"}, observed=observed)
    assert final_state == "Failed", (
        f"expected a trust to an unreachable remote domain to autonomously settle into "
        f"'Failed', got {final_state!r} (states observed: {observed!r})"
    )
    assert "Creating" in observed, (
        f"expected to observe trust {trust_id} pass through 'Creating' before it failed -- a "
        f"target that reports 'Failed' immediately with no creation phase is not running the "
        f"same handshake, states observed: {observed!r}"
    )
    assert "Verified" not in observed and "Created" not in observed, (
        f"a trust whose remote domain is unreachable must never be reported 'Verified' or "
        f"settle into 'Created', states observed: {observed!r}"
    )

    ds.delete_trust(TrustId=trust_id)
    _wait_for_trust_gone(ctx, directory_id, trust_id)


# ===== helpers =====


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


def _create_microsoft_ad(ctx, password="Sim2Real-TestPW1"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _default_vpc_two_azs(ctx)
    name = ctx.unique_name("sim2real-msad-") + ".test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=password,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[
            {"Key": "sim2real", "Value": "behavioral"},
            {"Key": "sim2real-check", "Value": CHECK},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _safe_delete_directory(ctx, directory_id))
    return directory_id


def _safe_delete_directory(ctx, directory_id):
    ds = ctx.client("ds")
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _safe_delete_trust(ctx, trust_id):
    ds = ctx.client("ds")
    try:
        ds.delete_trust(TrustId=trust_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityDoesNotExistException":
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


def _trust_state(ctx, directory_id, trust_id):
    # Real AWS requires DirectoryId on DescribeTrusts even when TrustIds is given -- botocore's
    # model marks both optional, but TrustIds alone gets InvalidParameterException("Directory ID
    # must be specified.").
    ds = ctx.client("ds")
    try:
        trusts = ds.describe_trusts(DirectoryId=directory_id, TrustIds=[trust_id])["Trusts"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityDoesNotExistException":
            return None
        raise
    return trusts[0]["TrustState"] if trusts else None


def _wait_for_trust_state(ctx, directory_id, trust_id, target_states, timeout_s=1200, interval_s=15, observed=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _trust_state(ctx, directory_id, trust_id)
        if observed is not None and last and (not observed or observed[-1] != last):
            observed.append(last)
        if last in target_states:
            return last
        if last == "Failed" and "Failed" not in target_states:
            raise AssertionError(f"trust {trust_id} entered Failed state")
        time.sleep(interval_s)
    raise AssertionError(f"trust {trust_id} did not reach {target_states} within {timeout_s}s (last={last})")


def _wait_for_trust_gone(ctx, directory_id, trust_id, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = "Deleting"
    while time.monotonic() < deadline:
        last = _trust_state(ctx, directory_id, trust_id)
        if last in (None, "Deleted"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"trust {trust_id} was not removed within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
