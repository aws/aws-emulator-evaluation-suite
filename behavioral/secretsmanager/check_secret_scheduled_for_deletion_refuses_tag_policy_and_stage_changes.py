"""secret-scheduled-for-deletion-refuses-tag-policy-and-stage-changes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, extra_tags=(), **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}, *extra_tags], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _refusal(fn):
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=150.0, interval_s=3.0):
    """Bounded poll; returns the last observation whether or not the predicate held."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


CHECK = "secret-scheduled-for-deletion-refuses-tag-policy-and-stage-changes"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

_MARKED = "You can't perform this operation on the secret because it was marked for deletion."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A secret scheduled for deletion refuses tag, policy and stage calls without effect while
    Describe/ListSecretVersionIds work; after RestoreSecret tagging works and no policy exists.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-schedmut-")
    created = _create_secret(sm, ctx, name, [{"Key": "owner", "Value": "team-a"}],
                             SecretString="sim2real-not-a-real-secret")
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
            "Action": "secretsmanager:DeleteResourcePolicy",
            "Resource": "*",
        }],
    })

    sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)

    attempts = [
        ("TagResource", lambda: sm.tag_resource(SecretId=name, Tags=[{"Key": "late", "Value": "x"}])),
        ("UntagResource", lambda: sm.untag_resource(SecretId=name, TagKeys=["owner"])),
        ("PutResourcePolicy", lambda: sm.put_resource_policy(SecretId=name, ResourcePolicy=policy)),
        ("GetResourcePolicy", lambda: sm.get_resource_policy(SecretId=name)),
        ("UpdateSecretVersionStage", lambda: sm.update_secret_version_stage(
            SecretId=name, VersionStage="blue", MoveToVersionId=created["VersionId"])),
    ]
    for label, attempt in attempts:
        code, message = _refusal(attempt)
        assert code == "InvalidRequestException", (
            f"{label} on a secret scheduled for deletion must be refused, got {code!r}"
        )
        assert message == _MARKED, f"unexpected {label} message: {message!r}"

    pending = sm.describe_secret(SecretId=name)
    assert pending.get("DeletedDate") is not None, "the secret must still be scheduled for deletion"
    assert {t["Key"]: t["Value"] for t in pending.get("Tags", [])} == {
        "sim2real": CHECK, "owner": "team-a"}, (
        f"refused tag calls must leave the tags unchanged, got {pending.get('Tags')!r}"
    )
    assert pending["VersionIdsToStages"] == {created["VersionId"]: ["AWSCURRENT"]}, (
        "the refused stage move must leave the staging labels unchanged"
    )
    versions = sm.list_secret_version_ids(SecretId=name)["Versions"]
    assert [v["VersionId"] for v in versions] == [created["VersionId"]], (
        "ListSecretVersionIds must still be served while the secret is scheduled"
    )

    # Positive control: the same mutation succeeds once the secret is restored.
    sm.restore_secret(SecretId=name)
    sm.tag_resource(SecretId=name, Tags=[{"Key": "late", "Value": "x"}])
    restored = {t["Key"]: t["Value"] for t in sm.describe_secret(SecretId=name).get("Tags", [])}
    assert restored.get("late") == "x", f"TagResource after RestoreSecret must apply, got {restored!r}"
    assert "ResourcePolicy" not in sm.get_resource_policy(SecretId=name), (
        "the PutResourcePolicy refused while scheduled must not have attached a policy"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
