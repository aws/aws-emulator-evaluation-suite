"""resource-policy-stale-revision-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-policy-stale-revision-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["amp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a stale revisionId (optimistic-lock mismatch) is rejected with
    ValidationException, leaving the current policy document untouched; supplying the correct,
    current revisionId (positive control, same file) updates it."""
    amp = ctx.client("amp")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    workspace_id = amp.create_workspace(
        alias=ctx.unique_name("sim2real-amp-ws-"), tags={"sim2real-owner": "behavioral"}
    )["workspaceId"]
    ctx.on_cleanup(lambda: amp.delete_workspace(workspaceId=workspace_id))
    _poll_until(
        lambda: amp.describe_workspace(workspaceId=workspace_id)["workspace"]["status"]["statusCode"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    workspace_arn = amp.describe_workspace(workspaceId=workspace_id)["workspace"]["arn"]

    # Setup: create the policy, then a legitimate update to get a fresh, current revisionId.
    stale_revision = amp.put_resource_policy(
        workspaceId=workspace_id, policyDocument=json.dumps(_policy_doc(account_id, workspace_arn, "aps:GetSeries"))
    )["revisionId"]
    _poll_until(
        lambda: amp.describe_resource_policy(workspaceId=workspace_id)["policyStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    current_revision = amp.put_resource_policy(
        workspaceId=workspace_id,
        policyDocument=json.dumps(_policy_doc(account_id, workspace_arn, "aps:QueryMetrics")),
        revisionId=stale_revision,
    )["revisionId"]
    _poll_until(
        lambda: amp.describe_resource_policy(workspaceId=workspace_id)["policyStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    assert current_revision != stale_revision, (
        f"expected the legitimate update to advance the revisionId, still {current_revision!r}"
    )

    # Break exactly one thing: reuse the now-stale revisionId.
    code, message = _error(
        lambda: amp.put_resource_policy(
            workspaceId=workspace_id,
            policyDocument=json.dumps(_policy_doc(account_id, workspace_arn, "aps:RemoteWrite")),
            revisionId=stale_revision,
        )
    )
    assert code == "ValidationException", f"expected ValidationException on stale revisionId, got {code}"
    expected = "Can't conditionally update a workspace resource policy with a wrong revisionId."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the document is still the one from the correct update, unrevised.
    unchanged = amp.describe_resource_policy(workspaceId=workspace_id)
    assert unchanged["revisionId"] == current_revision, (
        f"expected the rejected update to leave revisionId at {current_revision!r}, got {unchanged['revisionId']!r}"
    )
    unchanged_action = json.loads(unchanged["policyDocument"])["Statement"][0]["Action"]
    assert unchanged_action == "aps:QueryMetrics", (
        f"expected the rejected update to leave the policy document unrevised, got action {unchanged_action!r}"
    )

    # Positive control: the correct, current revisionId updates the policy successfully.
    amp.put_resource_policy(
        workspaceId=workspace_id,
        policyDocument=json.dumps(_policy_doc(account_id, workspace_arn, "aps:RemoteWrite")),
        revisionId=current_revision,
    )
    _poll_until(
        lambda: amp.describe_resource_policy(workspaceId=workspace_id)["policyStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
    )
    final = amp.describe_resource_policy(workspaceId=workspace_id)
    final_action = json.loads(final["policyDocument"])["Statement"][0]["Action"]
    assert final_action == "aps:RemoteWrite", (
        f"expected the restored update with the correct revisionId to apply, got action {final_action!r}"
    )
    assert final["revisionId"] != current_revision, (
        f"expected the successful restore to advance revisionId past {current_revision!r}"
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

