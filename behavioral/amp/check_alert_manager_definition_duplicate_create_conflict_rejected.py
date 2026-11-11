"""alert-manager-definition-duplicate-create-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alert-manager-definition-duplicate-create-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["amp"]


def _am_yaml(topic_arn: str, region: str, tag: str) -> bytes:
    return f"""alertmanager_config: |
  route:
    receiver: '{tag}-receiver'
  receivers:
    - name: '{tag}-receiver'
      sns_configs:
      - topic_arn: {topic_arn}
        sigv4:
          region: {region}
""".encode("utf-8")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAlertManagerDefinition on a workspace that already has one is rejected with
    ConflictException, leaving the original definition untouched; PutAlertManagerDefinition
    (the correct upsert path) still updates it (positive control, same file)."""
    amp = ctx.client("amp")
    sns = ctx.client("sns")
    region = sns.meta.region_name
    topic_tags = [{"Key": "sim2real-owner", "Value": "behavioral"}]
    topic_v1 = sns.create_topic(Name=ctx.unique_name("sim2real-behav-amtopic-v1"), Tags=topic_tags)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_v1))
    topic_v2 = sns.create_topic(Name=ctx.unique_name("sim2real-behav-amtopic-v2"), Tags=topic_tags)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_v2))
    am_yaml_v1 = _am_yaml(topic_v1, region, "v1")
    am_yaml_v2 = _am_yaml(topic_v2, region, "v2")
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real-owner": "behavioral"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    amp.create_alert_manager_definition(workspaceId=workspace_id, data=am_yaml_v1)
    _poll_until(
        lambda: amp.describe_alert_manager_definition(workspaceId=workspace_id)["alertManagerDefinition"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=180,
    )

    # Break exactly one thing: call Create again instead of Put.
    code, message = _error(lambda: amp.create_alert_manager_definition(workspaceId=workspace_id, data=am_yaml_v2))
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = "This alert manager definition already exists for this workspace."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the original v1 definition is unchanged.
    unchanged = amp.describe_alert_manager_definition(workspaceId=workspace_id)["alertManagerDefinition"]["data"]
    if isinstance(unchanged, str):
        unchanged = unchanged.encode("utf-8")
    assert bytes(unchanged) == am_yaml_v1, (
        f"expected the definition to be unchanged after the rejected Create, "
        f"got {bytes(unchanged)!r} instead of {am_yaml_v1!r}"
    )

    # Positive control: PutAlertManagerDefinition (upsert) succeeds and updates the content.
    amp.put_alert_manager_definition(workspaceId=workspace_id, data=am_yaml_v2)
    _poll_until(
        lambda: amp.describe_alert_manager_definition(workspaceId=workspace_id)["alertManagerDefinition"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=180,
    )
    updated = amp.describe_alert_manager_definition(workspaceId=workspace_id)["alertManagerDefinition"]["data"]
    if isinstance(updated, str):
        updated = updated.encode("utf-8")
    assert bytes(updated) == am_yaml_v2, (
        f"expected Put to upsert the definition to v2, got {bytes(updated)!r} instead of {am_yaml_v2!r}"
    )


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
