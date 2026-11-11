"""retention-settings-put-get-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "retention-settings-put-get-roundtrip"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAppInstanceRetentionSettings persists the channel RetentionDays value that
    GetAppInstanceRetentionSettings then returns."""
    # chime-sdk-identity's control plane exists only in us-east-1.
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=arn))

    put_resp = client.put_app_instance_retention_settings(
        AppInstanceArn=arn,
        AppInstanceRetentionSettings={"ChannelRetentionSettings": {"RetentionDays": 30}},
    )
    put_days = put_resp["AppInstanceRetentionSettings"]["ChannelRetentionSettings"]["RetentionDays"]
    assert put_days == 30, f"expected PutAppInstanceRetentionSettings to echo RetentionDays=30, got {put_days}"

    get_resp = client.get_app_instance_retention_settings(AppInstanceArn=arn)
    get_days = get_resp["AppInstanceRetentionSettings"]["ChannelRetentionSettings"]["RetentionDays"]
    assert get_days == 30, (
        f"expected GetAppInstanceRetentionSettings to reflect the persisted RetentionDays=30, got {get_days}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
