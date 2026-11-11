"""update-ipset-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-ipset-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """UpdateIPSet against an ipSetId that was never created is rejected with
    BadRequestException, not silently accepted."""
    gd = ctx.client("guardduty")
    resource_tags = {"sim2real:managed": "true", "sim2real:check": CHECK}

    detector_id = gd.create_detector(Enable=True, Tags=resource_tags)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    bogus_ipset_id = ctx.unique_name("sim2real-never-existed-ipset-")
    error = _client_error(
        lambda: gd.update_ip_set(
            DetectorId=detector_id,
            IpSetId=bogus_ipset_id,
            Name="sim2real-should-not-apply",
        )
    )
    assert error["Code"] == "BadRequestException", (
        f"expected BadRequestException, got {error['Code']!r}"
    )
    expected = "The request is rejected since no such resource found."
    assert error.get("Message") == expected, (
        f"expected message {expected!r}, got {error.get('Message')!r}"
    )

    # Effect absent: listing IPSets for the detector shows nothing (the bogus ID
    # was never created, and nothing should have materialized as a side effect).
    ip_set_ids = gd.list_ip_sets(DetectorId=detector_id).get("IpSetIds", [])
    assert bogus_ipset_id not in ip_set_ids, (
        f"expected {bogus_ipset_id!r} absent from {ip_set_ids!r}, but the rejected "
        "UpdateIPSet call materialized it anyway"
    )

    # Positive control: UpdateIPSet on a real, previously created IPSet succeeds and
    # persists the change.
    original_name = ctx.unique_name("sim2real-ipset-")
    ip_set_id = gd.create_ip_set(
        DetectorId=detector_id,
        Name=original_name,
        Format="TXT",
        Location="https://sim2real-nonexistent-bucket.s3.amazonaws.com/list.txt",
        Activate=False,
        Tags=resource_tags,
    )["IpSetId"]
    ctx.on_cleanup(lambda: gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id))

    updated_name = ctx.unique_name("sim2real-ipset-updated-")
    gd.update_ip_set(DetectorId=detector_id, IpSetId=ip_set_id, Name=updated_name)
    fetched = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    assert fetched["Name"] == updated_name, (
        f"expected the real IPSet's name to persist as {updated_name!r}, "
        f"got {fetched['Name']!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
