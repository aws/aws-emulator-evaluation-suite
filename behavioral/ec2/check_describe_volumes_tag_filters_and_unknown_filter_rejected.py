"""describe-volumes-tag-filters-and-unknown-filter-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-volumes-tag-filters-and-unknown-filter-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

ERR_INVALID_PARAM = 'InvalidParameterValue'
BAD_FILTER = 'not-a-real-filter'


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _an_az(ec2):
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    return zones[0]


def _wait_volume_state(ec2, volume_id, state, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                last = "__not_yet_visible__"
                time.sleep(2)
                continue
            raise
        if last == state:
            return
        time.sleep(2)
    raise AssertionError(f"volume {volume_id} never reached {state!r} in {timeout_s}s (last {last!r})")


def _ids(ec2, filters):
    return sorted(
        v["VolumeId"] for v in ec2.describe_volumes(Filters=filters)["Volumes"]
    )


def _delete_volume(ec2, volume_id):
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVolumes filters AND together, Values OR together, tag values honour `*`/`?` wildcards,
    a non-matching filter yields the empty set, and an unknown filter name is rejected with
    InvalidParameterValue naming it, rather than silently ignored (returning every volume).
    """
    ec2 = ctx.client("ec2")
    az = _an_az(ec2)
    suite = ctx.unique_name("sim2real-behav-")

    def _mk(role):
        vol = ec2.create_volume(
            AvailabilityZone=az, Size=1, VolumeType="gp3",
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "sim2real", "Value": "1"},
                        {"Key": "sim2real-suite", "Value": suite},
                        {"Key": "sim2real-role", "Value": role},
                    ],
                }
            ],
        )["VolumeId"]
        ctx.on_cleanup(lambda v=vol: _delete_volume(ec2, v))
        _wait_volume_state(ec2, vol, "available")
        return vol

    alpha = _mk("alpha")
    beta = _mk("beta")
    both = sorted([alpha, beta])

    suite_filter = {"Name": "tag:sim2real-suite", "Values": [suite]}

    # --- a single tag filter selects exactly the tagged set, nothing else ---
    got = _ids(ec2, [suite_filter])
    assert got == both, f"tag:sim2real-suite={suite} must return exactly {both}, got {got}"

    # --- two filters AND together (not OR) ---
    got = _ids(ec2, [suite_filter, {"Name": "tag:sim2real-role", "Values": ["alpha"]}])
    assert got == [alpha], (
        f"tag:suite AND tag:role=alpha must AND to [{alpha}], got {got} "
        "(an OR/ignored second filter returns both)"
    )

    # --- multiple Values on one filter OR together ---
    got = _ids(ec2, [suite_filter, {"Name": "tag:sim2real-role", "Values": ["alpha", "beta"]}])
    assert got == both, f"two Values on one filter must OR to {both}, got {got}"

    # --- wildcards are honoured in tag values ---
    got = _ids(ec2, [suite_filter, {"Name": "tag:sim2real-role", "Values": ["al*"]}])
    assert got == [alpha], f"wildcard 'al*' must match only [{alpha}], got {got}"
    got = _ids(ec2, [suite_filter, {"Name": "tag:sim2real-role", "Values": ["?eta"]}])
    assert got == [beta], f"single-char wildcard '?eta' must match only [{beta}], got {got}"

    # --- a filter that matches nothing returns EMPTY, not everything ---
    got = _ids(ec2, [suite_filter, {"Name": "tag:sim2real-role", "Values": ["gamma"]}])
    assert got == [], f"a non-matching filter must return the empty set, got {got}"
    got = _ids(ec2, [{"Name": "tag-key", "Values": [f"{suite}-absent-key"]}])
    assert got == [], f"tag-key on an absent key must return the empty set, got {got}"

    # --- break exactly one thing: an UNKNOWN filter NAME ---
    try:
        ec2.describe_volumes(Filters=[suite_filter, {"Name": BAD_FILTER, "Values": ["x"]}])
    except ClientError as exc:
        assert _code(exc) == ERR_INVALID_PARAM, (
            f"expected {ERR_INVALID_PARAM} for unknown filter {BAD_FILTER!r}, got {_code(exc)}"
        )
        msg = exc.response.get("Error", {}).get("Message", "")
        assert msg == f"The filter '{BAD_FILTER}' is invalid", (
            f"the rejection must name the offending filter {BAD_FILTER!r}, message was {msg!r}"
        )
    else:
        raise AssertionError(
            f"DescribeVolumes with unknown filter {BAD_FILTER!r} must be rejected, "
            "not silently ignored (that returns the caller's whole account)"
        )

    # --- control: the valid filter still resolves correctly after the rejection ---
    got = _ids(ec2, [suite_filter])
    assert got == both, f"after the rejected call the valid filter must still return {both}, got {got}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
