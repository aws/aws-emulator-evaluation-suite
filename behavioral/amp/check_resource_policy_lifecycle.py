"""resource-policy-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-policy-lifecycle"
GROUP = "state"
SERVICES = ["amp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy creates (CREATING->ACTIVE) and DeleteResourcePolicy removes the
    resource-based policy attached to a workspace, leaving it gone and unusable."""
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

    policy_doc = _policy_doc(account_id, workspace_arn, "aps:GetSeries")
    put_resp = amp.put_resource_policy(workspaceId=workspace_id, policyDocument=json.dumps(policy_doc))
    assert put_resp["policyStatus"] in (
        "CREATING",
        "ACTIVE",
    ), f"expected CREATING or ACTIVE from PutResourcePolicy, got {put_resp['policyStatus']!r}"
    revision_id = put_resp["revisionId"]

    status = _poll_until(
        lambda: amp.describe_resource_policy(workspaceId=workspace_id)["policyStatus"],
        lambda s: s in ("ACTIVE",),
        timeout_s=120,
    )
    assert status == "ACTIVE", f"expected policyStatus ACTIVE after PutResourcePolicy, got {status!r}"
    described = amp.describe_resource_policy(workspaceId=workspace_id)
    described_action = json.loads(described["policyDocument"])["Statement"][0]["Action"]
    assert described_action == "aps:GetSeries", f"expected the put document's action, got {described_action!r}"
    assert (
        described["revisionId"] == revision_id
    ), f"expected DescribeResourcePolicy revisionId to match PutResourcePolicy's, got {described['revisionId']!r} != {revision_id!r}"

    amp.delete_resource_policy(workspaceId=workspace_id, revisionId=revision_id)
    code, message = _error(lambda: amp.describe_resource_policy(workspaceId=workspace_id), wait_s=120)
    assert code == "ResourceNotFoundException", f"expected DescribeResourcePolicy to 404 post-delete, got {code!r}"
    expected = "Workspace resource policy not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A mutation on the now-dead policy also fails, not just the read.
    redelete_code, message = _error(lambda: amp.delete_resource_policy(workspaceId=workspace_id, revisionId=revision_id))
    assert (
        redelete_code == "ResourceNotFoundException"
    ), f"expected a second DeleteResourcePolicy to also 404, got {redelete_code!r}"
    expected = "Workspace resource policy not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _error(fn, *, wait_s=0.0, interval_s=3.0):
    """Call fn(), which must fail; return its botocore error (code, message). With wait_s a
    success is retried until the refusal appears, and a success past the deadline raises, so a
    target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response["Error"]
            return error["Code"], error.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


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
