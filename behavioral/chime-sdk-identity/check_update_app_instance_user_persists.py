"""update-app-instance-user-persists."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "update-app-instance-user-persists"
GROUP = "state"
SERVICES = ["chime-sdk-identity"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAppInstanceUser persists the new Name/Metadata and advances LastUpdatedTimestamp."""
    client = ctx.client("chime-sdk-identity", region="us-east-1")
    instance_arn = client.create_app_instance(
        Name=ctx.unique_name("sim2real-chime-ai-"),
        Metadata="",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceArn"]
    ctx.on_cleanup(lambda: client.delete_app_instance(AppInstanceArn=instance_arn))

    user_arn = client.create_app_instance_user(
        AppInstanceArn=instance_arn,
        AppInstanceUserId=ctx.unique_name("user-"),
        Name="original-name",
        Metadata="original-metadata",
        ClientRequestToken=uuid.uuid4().hex,
        Tags=[{"Key": "sim2real-env", "Value": "behavioral"}],
    )["AppInstanceUserArn"]

    before = client.describe_app_instance_user(AppInstanceUserArn=user_arn)["AppInstanceUser"]

    # LastUpdatedTimestamp has millisecond resolution, so a single update issued in the same
    # millisecond as the create could tie. Re-issue the (idempotent, same-target) update inside
    # a bounded poll until the server-observed timestamp actually advances, rather than paying a
    # fixed sleep on every run.
    def _attempt():
        client.update_app_instance_user(AppInstanceUserArn=user_arn, Name="new-name", Metadata="new-metadata")
        return client.describe_app_instance_user(AppInstanceUserArn=user_arn)["AppInstanceUser"]

    after = _poll_until(
        _attempt,
        lambda desc: desc["LastUpdatedTimestamp"] > before["LastUpdatedTimestamp"],
        timeout_s=15.0,
        interval_s=0.5,
    )
    assert after["Name"] == "new-name", f"expected Name 'new-name', got {after['Name']!r}"
    assert after["Metadata"] == "new-metadata", (
        f"expected Metadata 'new-metadata', got {after['Metadata']!r}"
    )
    assert after["LastUpdatedTimestamp"] > before["LastUpdatedTimestamp"], (
        f"expected LastUpdatedTimestamp to advance past {before['LastUpdatedTimestamp']!r}, "
        f"got {after['LastUpdatedTimestamp']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 15.0, interval_s: float = 0.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
