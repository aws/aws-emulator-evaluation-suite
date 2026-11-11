"""resource-policy-concurrent-update-optimistic-lock."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "resource-policy-concurrent-update-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["amp"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N racing PutResourcePolicy calls that all present the same current revisionId: exactly
    one wins (advances the revision), and every other racer gets ConflictException -- the
    optimistic-lock contract holds under contention."""
    amp = ctx.client("amp")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real-check": CHECK}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    workspace_arn = amp.describe_workspace(workspaceId=workspace_id)["workspace"]["arn"]

    base_revision = amp.put_resource_policy(
        workspaceId=workspace_id, policyDocument=json.dumps(_policy_doc(account_id, workspace_arn, "aps:GetSeries"))
    )["revisionId"]
    _poll_until(
        lambda: amp.describe_resource_policy(workspaceId=workspace_id)["policyStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )

    racer_actions = ["aps:QueryMetrics", "aps:GetLabels", "aps:GetSeries", "aps:GetMetricMetadata", "aps:RemoteWrite"]
    n_racers = len(racer_actions)

    def racer(i):
        try:
            resp = amp.put_resource_policy(
                workspaceId=workspace_id,
                policyDocument=json.dumps(_policy_doc(account_id, workspace_arn, racer_actions[i])),
                revisionId=base_revision,
            )
            return (i, "ok", resp["revisionId"])
        except Exception as exc:  # noqa: BLE001 - classify below
            error = getattr(exc, "response", {}).get("Error", {})
            messages[i] = error.get("Message")
            return (i, "error", error.get("Code"))

    messages = {}

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(racer, range(n_racers)))

    wins = [r for r in results if r[1] == "ok"]
    losses = [r for r in results if r[1] == "error"]
    assert len(wins) == 1, f"expected exactly one winner among racers, got {len(wins)}: {results}"
    assert len(losses) == n_racers - 1, f"expected {n_racers - 1} losers, got {len(losses)}: {results}"
    assert all(code == "ConflictException" for _, _, code in losses), f"unexpected loser codes: {losses}"
    expected_message = "Can't update the workspace resource policy in non-(ACTIVE) state. Current status is UPDATING"
    for i, _, _ in losses:
        assert messages[i] == expected_message, messages[i]

    winner_index, _, winner_revision = wins[0]
    _poll_until(
        lambda: amp.describe_resource_policy(workspaceId=workspace_id)["policyStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    final = amp.describe_resource_policy(workspaceId=workspace_id)
    assert final["revisionId"] == winner_revision, (
        f"expected the surviving revisionId to be the winner's own ({winner_revision!r}), "
        f"got {final['revisionId']!r}"
    )
    final_action = json.loads(final["policyDocument"])["Statement"][0]["Action"]
    assert final_action == racer_actions[winner_index], (
        f"revisionId matched the winner but the committed document does not: "
        f"expected action {racer_actions[winner_index]!r} (racer {winner_index}), got {final_action!r}"
    )


def _policy_doc(account_id, workspace_arn, action):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealAllow",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": action,
                "Resource": workspace_arn,
            }
        ],
    }


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

