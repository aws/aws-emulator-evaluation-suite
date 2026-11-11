"""op-contract-describeVolumeAttribute."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeVolumeAttribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVolumeAttribute returns the requested attribute for a real EBS volume,
    and rejects a nonexistent (but well-formed) volume id with the specific
    InvalidVolume.NotFound boundary, distinct from a malformed-request rejection."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    created = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vol-")}],
            }
        ],
    )
    volume_id = created["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))

    ec2.get_waiter("volume_available").wait(
        VolumeIds=[volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )

    # success path: a freshly created volume defaults autoEnableIO to False, and the
    # response echoes back the same volume id
    resp = ec2.describe_volume_attribute(VolumeId=volume_id, Attribute="autoEnableIO")
    assert resp["VolumeId"] == volume_id, f"expected VolumeId {volume_id!r}, got {resp['VolumeId']!r}"
    assert resp["AutoEnableIO"]["Value"] is False, resp["AutoEnableIO"]

    # the productCodes attribute must also round-trip cleanly (empty for a plain volume)
    resp_pc = ec2.describe_volume_attribute(VolumeId=volume_id, Attribute="productCodes")
    assert resp_pc["VolumeId"] == volume_id, f"expected VolumeId {volume_id!r}, got {resp_pc['VolumeId']!r}"
    assert resp_pc.get("ProductCodes", []) == [], f"expected no product codes, got {resp_pc.get('ProductCodes')!r}"

    # error boundary #1: a syntactically well-formed but nonexistent volume id is
    # rejected with the resource-specific NotFound code ("InvalidVolume.NotFound"
    # per the EC2 API error reference), not a client-side validation error -- it
    # passes the syntax check and reaches the existence lookup, which finds
    # nothing. A hand-synthesized candidate id (e.g. built around a supposed
    # "reserved leading hex digit") is not a reliable way to probe this: AWS's
    # id-format validator has no documented carve-out for such a scheme, and a
    # fabricated id can just as easily be rejected as malformed instead of
    # reaching the existence lookup. To remove that ambiguity, allocate a
    # second, throwaway volume (which guarantees a genuinely well-formed id),
    # delete it, and wait for it to fully disappear before probing it -- this
    # is a real id that is guaranteed to pass the syntax check and guaranteed
    # to no longer exist.
    missing_volume = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-vol-missing-")}
                ],
            }
        ],
    )
    missing_volume_id = missing_volume["VolumeId"]
    ec2.get_waiter("volume_available").wait(
        VolumeIds=[missing_volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )
    ec2.delete_volume(VolumeId=missing_volume_id)

    def _volume_is_gone():
        try:
            ec2.describe_volumes(VolumeIds=[missing_volume_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVolume.NotFound":
                return True
            raise
        return False

    assert _poll_until(_volume_is_gone, timeout_s=120, interval_s=5), (
        "deleted volume did not fully disappear from describe_volumes within timeout"
    )

    code, message = _client_error(
        lambda: ec2.describe_volume_attribute(VolumeId=missing_volume_id, Attribute="autoEnableIO")
    )
    assert code == "InvalidVolume.NotFound", f"expected InvalidVolume.NotFound, got {code!r}"
    expected_not_found = f"The volume '{missing_volume_id}' does not exist."
    assert message == expected_not_found, f"expected message {expected_not_found!r}, got {message!r}"

    rng = random.Random(f"{ctx.unique_name('seed')}-malformed-volume")

    # error boundary #2: a syntactically well-formed id for a *different*
    # resource type (an EC2 instance id, "i-...") fails the volume-specific
    # id-format check up front on real AWS, never reaching the existence
    # lookup at all. (Empirically, AWS's id syntax check for volumes does
    # not restrict the suffix to a strict hex alphabet -- a "vol-" id with
    # non-hex-but-alphanumeric suffix characters still passes the syntax
    # check and falls through to the NotFound boundary instead, so it is
    # not a reliable malformed-boundary probe. A mismatched resource-type
    # prefix, however, can never pass the volume id format check, removing
    # that ambiguity. On real AWS, the rejection for a wrong-resource-type
    # prefix surfaces as "InvalidParameterValue" -- e.g. "Invalid id:
    # \"i-...\" (expecting \"vol-...\")" -- rather than
    # "InvalidVolumeID.Malformed", which is reserved for ids that don't
    # match any recognizable resource-id shape at all.)
    malformed_id = "i-" + "".join(rng.choice("0123456789abcdef") for _ in range(17))
    code_malformed, message_malformed = _client_error(
        lambda: ec2.describe_volume_attribute(VolumeId=malformed_id, Attribute="autoEnableIO")
    )
    assert code_malformed == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {code_malformed!r}"
    )
    expected_malformed = f"Value ({malformed_id}) for parameter volumeId is invalid. Expected: 'vol-...'."
    assert message_malformed == expected_malformed, (
        f"expected message {expected_malformed!r}, got {message_malformed!r}"
    )


def _client_error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(predicate, timeout_s=120, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
