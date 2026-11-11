"""put-app-instance-retention-settings-range-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-app-instance-retention-settings-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAppInstanceRetentionSettings with RetentionDays 5476 fails with ValidationException and the exact
    "less than or equal to 5475" message (an error the API model does not list) and leaves the settings
    unchanged, while RetentionDays 90 is accepted and persists."""
    # chime-sdk-identity's control plane is us-east-1 only.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    before = client.get_app_instance_retention_settings(AppInstanceArn=instance_arn).get(
        "AppInstanceRetentionSettings"
    )

    code, message = _error(
        lambda: client.put_app_instance_retention_settings(
            AppInstanceArn=instance_arn,
            AppInstanceRetentionSettings={"ChannelRetentionSettings": {"RetentionDays": 5476}},
        )
    )
    assert code == "ValidationException", (
        f"expected RetentionDays=5476 (above the documented max of 5475) to be rejected with "
        f"ValidationException, got {code!r}"
    )
    expected_message = (
        "1 validation error detected: Value '5476' at "
        "'appInstanceRetentionSettings.channelRetentionSettings.retentionDays' failed to satisfy "
        "constraint: Member must have value less than or equal to 5475"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_rejected = client.get_app_instance_retention_settings(AppInstanceArn=instance_arn).get(
        "AppInstanceRetentionSettings"
    )
    assert after_rejected == before, (
        f"expected the rejected RetentionDays=5476 call to leave the retention settings "
        f"unchanged at {before!r}, got {after_rejected!r}"
    )

    # Positive control: an in-range value is accepted and persists.
    client.put_app_instance_retention_settings(
        AppInstanceArn=instance_arn,
        AppInstanceRetentionSettings={"ChannelRetentionSettings": {"RetentionDays": 90}},
    )
    after_valid = client.get_app_instance_retention_settings(AppInstanceArn=instance_arn)[
        "AppInstanceRetentionSettings"
    ]
    assert after_valid["ChannelRetentionSettings"]["RetentionDays"] == 90, (
        f"expected the in-range positive control RetentionDays=90 to persist, "
        f"got {after_valid!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects RetentionDays=5476, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
