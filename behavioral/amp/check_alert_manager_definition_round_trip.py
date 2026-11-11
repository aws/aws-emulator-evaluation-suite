"""alert-manager-definition-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "alert-manager-definition-round-trip"
GROUP = "data-plane"
SERVICES = ["amp"]


def _am_yaml(topic_arn: str, region: str) -> bytes:
    return f"""alertmanager_config: |
  route:
    receiver: 'default-receiver'
  receivers:
    - name: 'default-receiver'
      sns_configs:
      - topic_arn: {topic_arn}
        sigv4:
          region: {region}
""".encode("utf-8")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAlertManagerDefinition stores the exact YAML blob; DescribeAlertManagerDefinition
    returns it byte-for-byte once ACTIVE."""
    amp = ctx.client("amp")
    sns = ctx.client("sns")
    region = sns.meta.region_name
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-amtopic"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    am_yaml = _am_yaml(topic_arn, region)
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"),
        tags={"sim2real-check": CHECK},
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    amp.create_alert_manager_definition(workspaceId=workspace_id, data=am_yaml)

    status = _poll_until(
        lambda: amp.describe_alert_manager_definition(workspaceId=workspace_id)["alertManagerDefinition"]["status"]["statusCode"],
        lambda s: s in ("ACTIVE", "CREATION_FAILED"),
        timeout_s=180,
    )
    assert status == "ACTIVE", f"expected alert manager definition ACTIVE, got {status!r}"

    described = amp.describe_alert_manager_definition(workspaceId=workspace_id)["alertManagerDefinition"]
    stored = described["data"]
    if isinstance(stored, str):
        stored = stored.encode("utf-8")
    assert bytes(stored) == am_yaml, "stored Alertmanager config does not match what was submitted"


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
