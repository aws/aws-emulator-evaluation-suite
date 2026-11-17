"""update-detector-features-partial-change-rejects-unknown-additional-configuration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-detector-features-partial-change-rejects-unknown-additional-configuration"
GROUP = "detector"
SERVICES = ["guardduty"]

_UNKNOWN_ADDITIONAL_CONFIGURATION = (
    "BadRequestException",
    "The request was rejected because additional configuration was provided for a feature "
    "that does not support it.",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _additional_configuration(detector, feature_name):
    by_name = {f["Name"]: f for f in detector["Features"]}
    assert feature_name in by_name, f"{feature_name!r} missing from Features: {sorted(by_name)!r}"
    feature = by_name[feature_name]
    return feature["Status"], {a["Name"]: a["Status"] for a in feature.get("AdditionalConfiguration", [])}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """GetDetector reads back the RUNTIME_MONITORING agent-management settings and S3_DATA_EVENTS
    CreateDetector set; a partial UpdateDetector leaves the untouched agent settings as they were;
    an unrecognized AdditionalConfiguration name is rejected and changes nothing."""
    gd = ctx.client("guardduty")

    detector_id = gd.create_detector(
        Enable=True,
        FindingPublishingFrequency="SIX_HOURS",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        Features=[
            {
                "Name": "RUNTIME_MONITORING",
                "Status": "ENABLED",
                "AdditionalConfiguration": [
                    {"Name": "ECS_FARGATE_AGENT_MANAGEMENT", "Status": "ENABLED"},
                    {"Name": "EC2_AGENT_MANAGEMENT", "Status": "ENABLED"},
                    {"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"},
                ],
            },
            {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
        ],
    )["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    created = gd.get_detector(DetectorId=detector_id)
    rm_status, rm_addl = _additional_configuration(created, "RUNTIME_MONITORING")
    assert rm_status == "ENABLED", rm_status
    assert rm_addl == {
        "ECS_FARGATE_AGENT_MANAGEMENT": "ENABLED",
        "EC2_AGENT_MANAGEMENT": "ENABLED",
        "EKS_ADDON_MANAGEMENT": "DISABLED",
    }, rm_addl
    s3_status, _ = _additional_configuration(created, "S3_DATA_EVENTS")
    assert s3_status == "ENABLED", s3_status

    # Partial update: flip EKS_ADDON_MANAGEMENT and S3_DATA_EVENTS; the other two agent
    # settings are not named in this call.
    gd.update_detector(
        DetectorId=detector_id,
        Features=[
            {
                "Name": "RUNTIME_MONITORING",
                "Status": "ENABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "ENABLED"}],
            },
            {"Name": "S3_DATA_EVENTS", "Status": "DISABLED"},
        ],
    )

    after_update = gd.get_detector(DetectorId=detector_id)
    rm_status, rm_addl = _additional_configuration(after_update, "RUNTIME_MONITORING")
    assert rm_status == "ENABLED", rm_status
    assert rm_addl == {
        "ECS_FARGATE_AGENT_MANAGEMENT": "ENABLED",
        "EC2_AGENT_MANAGEMENT": "ENABLED",
        "EKS_ADDON_MANAGEMENT": "ENABLED",
    }, rm_addl
    s3_status, _ = _additional_configuration(after_update, "S3_DATA_EVENTS")
    assert s3_status == "DISABLED", s3_status

    # An unrecognized AdditionalConfiguration name is refused, and the refused call changes nothing.
    expect_error(
        lambda: gd.update_detector(
            DetectorId=detector_id,
            Features=[
                {
                    "Name": "RUNTIME_MONITORING",
                    "Status": "ENABLED",
                    "AdditionalConfiguration": [
                        {"Name": "NOT_A_REAL_AGENT_MANAGEMENT", "Status": "ENABLED"}
                    ],
                },
            ],
        ),
        *_UNKNOWN_ADDITIONAL_CONFIGURATION,
    )

    after_rejected = gd.get_detector(DetectorId=detector_id)
    rm_status, rm_addl = _additional_configuration(after_rejected, "RUNTIME_MONITORING")
    assert rm_status == "ENABLED", rm_status
    assert rm_addl == {
        "ECS_FARGATE_AGENT_MANAGEMENT": "ENABLED",
        "EC2_AGENT_MANAGEMENT": "ENABLED",
        "EKS_ADDON_MANAGEMENT": "ENABLED",
    }, rm_addl
    s3_status, _ = _additional_configuration(after_rejected, "S3_DATA_EVENTS")
    assert s3_status == "DISABLED", s3_status

    # Positive control: a recognized AdditionalConfiguration name in the same call shape succeeds.
    gd.update_detector(
        DetectorId=detector_id,
        Features=[
            {
                "Name": "RUNTIME_MONITORING",
                "Status": "ENABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"}],
            },
        ],
    )
    control = gd.get_detector(DetectorId=detector_id)
    rm_status, rm_addl = _additional_configuration(control, "RUNTIME_MONITORING")
    assert rm_status == "ENABLED", rm_status
    assert rm_addl["EKS_ADDON_MANAGEMENT"] == "DISABLED", rm_addl


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
