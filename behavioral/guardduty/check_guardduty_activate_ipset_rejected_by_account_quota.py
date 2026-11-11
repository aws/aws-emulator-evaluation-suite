"""guardduty-activate-ipset-rejected-by-account-quota."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardduty-activate-ipset-rejected-by-account-quota"
GROUP = "negative-classes"
SERVICES = ["guardduty"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """CreateIPSet(Activate=True) is rejected with InternalServerErrorException citing the
    account limits before the S3 Location is read, and creates nothing, while
    the same Location with Activate=False succeeds (positive control)."""
    gd = ctx.client("guardduty")
    detector_id = _get_or_create_detector(ctx, gd)

    before = set(gd.list_ip_sets(DetectorId=detector_id).get("IpSetIds", []))
    probe_location = (
        f"https://s3.{ctx.region}.amazonaws.com/sim2real-gd-noperm-probe-bucket/list.txt"
    )

    # Positive control: IPSet CRUD works for this account/detector in general -- only
    # *activation* is gated, not the API surface as a whole.
    control_name = ctx.unique_name("sim2real-gd-noperm-ctrl-")
    control_id = gd.create_ip_set(
        DetectorId=detector_id,
        Name=control_name,
        Format="TXT",
        Location=probe_location,
        Activate=False,
    )["IpSetId"]
    ctx.on_cleanup(lambda: _safe_delete_ip_set(gd, detector_id, control_id))
    assert gd.get_ip_set(DetectorId=detector_id, IpSetId=control_id)["Name"] == control_name, (
        "positive control: an inactive IPSet must be creatable and independently readable"
    )

    # The specific, deterministic refusal: activating ANY IPSet in this account is rejected
    # before the Location is dereferenced. Same Location, same detector -- only Activate flips.
    blocked_name = ctx.unique_name("sim2real-gd-noperm-blocked-")
    err = _client_error(
        lambda: gd.create_ip_set(
            DetectorId=detector_id,
            Name=blocked_name,
            Format="TXT",
            Location=probe_location,
            Activate=True,
        )
    )
    assert err.get("Code") == "InternalServerErrorException", (
        f"expected InternalServerErrorException activating an IPSet, got {err}"
    )
    expected = (
        "The request is rejected because it\u2019s an attempt to create resources beyond the "
        "current AWS account limits."
    )
    assert err.get("Message") == expected, (
        f"expected message {expected!r}, got {err.get('Message')!r}"
    )

    # Effect absent, via an independent read: the rejected attempt created nothing beyond
    # the positive control that had already landed.
    after = set(gd.list_ip_sets(DetectorId=detector_id).get("IpSetIds", []))
    assert after == before | {control_id}, (
        f"the rejected Activate=True call must not have created an IPSet: "
        f"before={before} control={control_id} after={after}"
    )


# ===== helpers =====

def _get_or_create_detector(ctx, gd) -> str:
    ids = gd.list_detectors().get("DetectorIds", [])
    if ids:
        return ids[0]
    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    ctx.on_cleanup(lambda: _safe_delete_detector(gd, detector_id))
    return detector_id


def _safe_delete_detector(gd, detector_id: str) -> None:
    try:
        gd.delete_detector(DetectorId=detector_id)
    except ClientError as err:
        # GuardDuty reports a detector that is already gone as BadRequestException.
        if err.response["Error"]["Code"] != "BadRequestException":
            raise


def _safe_delete_ip_set(gd, detector_id: str, ip_set_id: str) -> None:
    try:
        gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    except ClientError as err:
        # GuardDuty reports an IPSet that is already gone as BadRequestException.
        if err.response["Error"]["Code"] != "BadRequestException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not be
    reduced to an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected real AWS to reject this call, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
