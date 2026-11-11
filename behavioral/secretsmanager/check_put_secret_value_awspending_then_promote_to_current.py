"""put-secret-value-awspending-then-promote-to-current."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# This walks the rotation staging protocol by hand: it configures no rotation and names no Lambda,
# so no rotation function is invoked and no external credential is rotated.


def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone.
    Forced: DeleteSecret's minimum recovery window is 7 days and a PendingDeletion secret bills."""
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
                f"secret {secret_id} still present {timeout_s}s after "
                f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(Name=name, **kwargs)
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _error_code(fn):
    """Call fn(); return the botocore Error.Code if a ClientError was raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _read_stage(sm, secret_id, *, stage=None, expect_version, timeout_s=30.0, interval_s=2.0):
    """GetSecretValue for a staging label once it resolves ``expect_version``.
    Retries only the staging-label read-after-write lag (ResourceNotFoundException or the pre-move
    version) until the deadline; any other error propagates immediately."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            kwargs = {"VersionStage": stage} if stage else {}
            got = sm.get_secret_value(SecretId=secret_id, **kwargs)
            if got["VersionId"] == expect_version:
                return got
            last = got["VersionId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            last = "ResourceNotFoundException"
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"staging label {stage or 'AWSCURRENT (default)'} never resolved "
                f"{expect_version} within {timeout_s}s; last observation was {last!r}"
            )
        time.sleep(interval_s)


def _await_stage_gone(sm, secret_id, stage, *, stale_version, timeout_s=30.0, interval_s=2.0):
    """Return the error code and message once ``stage`` no longer resolves, asserting it never mis-resolves.
    While the detached binding lingers the read must return exactly ``stale_version``."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            got = sm.get_secret_value(SecretId=secret_id, VersionStage=stage)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        assert got["VersionId"] == stale_version, (
            f"a detached staging label must never fall back to another version: {stage} resolved "
            f"{got['VersionId']}, expected either a refusal or the stale {stale_version}"
        )
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"staging label {stage} was removed but still resolved {stale_version} after "
                f"{timeout_s}s"
            )
        time.sleep(interval_s)


def _stage_map(sm, secret_id):
    """Exact {version_id: frozenset(labels)} from DescribeSecret."""
    desc = sm.describe_secret(SecretId=secret_id)
    return {k: frozenset(v) for k, v in desc["VersionIdsToStages"].items()}


def _settled_stage_map(sm, secret_id, ok, *, timeout_s=30.0, interval_s=2.0):
    """The stage map once ``ok(map)`` holds, else the LAST map observed at the deadline.
    UpdateSecretVersionStage is asynchronous with respect to DescribeSecret: a promotion can
    still be reported against the old version for a second or two."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = _stage_map(sm, secret_id)
        if ok(got) or time.monotonic() >= deadline:
            return got
        time.sleep(interval_s)


CHECK = "put-secret-value-awspending-then-promote-to-current"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A version staged AWSPENDING does not shadow AWSCURRENT, can lose and regain the label, and
    can be promoted to AWSCURRENT, demoting the old version to exactly AWSPREVIOUS.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_UpdateSecretVersionStage.html
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-pending-")

    current_value = "sim2real-not-a-real-secret-current"
    pending_value = "sim2real-not-a-real-secret-pending"

    created = _create_secret(sm, ctx, name, SecretString=current_value)
    arn = created["ARN"]
    v1 = created["VersionId"]

    # setSecret: stage a new version as AWSPENDING only.
    v2 = sm.put_secret_value(
        SecretId=arn, SecretString=pending_value, VersionStages=["AWSPENDING"]
    )["VersionId"]
    assert v2 != v1, "PutSecretValue must mint a new version id"

    _want_staged = {v1: frozenset({"AWSCURRENT"}), v2: frozenset({"AWSPENDING"})}
    staged = _settled_stage_map(sm, arn, lambda m: m == _want_staged)
    assert staged == {v1: frozenset({"AWSCURRENT"}), v2: frozenset({"AWSPENDING"})}, (
        "staging a version AWSPENDING must leave AWSCURRENT on the original version; "
        f"expected v1=AWSCURRENT v2=AWSPENDING, got {staged}"
    )

    # The load-bearing safety property: default readers must NOT see the pending value.
    default_read = sm.get_secret_value(SecretId=arn)
    assert default_read["ARN"] == arn, (
        f"read resolved a different secret: {default_read['ARN']} != {arn}"
    )
    assert default_read["VersionId"] == v1, (
        "a default GetSecretValue must still resolve AWSCURRENT (v1) while v2 is only "
        f"AWSPENDING, got {default_read['VersionId']}"
    )
    assert default_read["SecretString"] == current_value, (
        "the pending value must not be served to default readers mid-rotation"
    )
    assert default_read["VersionStages"] == ["AWSCURRENT"], (
        f"the default read must report only AWSCURRENT, got {default_read.get('VersionStages')}"
    )

    # testSecret: the pending value is reachable, but only by asking for it.
    pending_read = sm.get_secret_value(SecretId=arn, VersionStage="AWSPENDING")
    assert pending_read["VersionId"] == v2
    assert pending_read["SecretString"] == pending_value
    assert pending_read["VersionStages"] == ["AWSPENDING"], (
        f"expected only AWSPENDING on v2, got {pending_read.get('VersionStages')}"
    )

    # Label removal: RemoveFromVersionId with MoveToVersionId omitted detaches it.
    sm.update_secret_version_stage(
        SecretId=arn, VersionStage="AWSPENDING", RemoveFromVersionId=v2
    )
    detached = _settled_stage_map(
        sm, arn, lambda m: m.get(v1) == frozenset({"AWSCURRENT"}) and not m.get(v2))
    assert detached.get(v1) == frozenset({"AWSCURRENT"}), (
        f"removing AWSPENDING must not disturb AWSCURRENT, got {detached}"
    )
    assert not detached.get(v2), (
        f"v2 must be left with no staging label after AWSPENDING is removed, got {detached.get(v2)}"
    )
    # Same read-after-write lag as the promotion below, in the other direction: a just-detached
    # label can still resolve its old version for a second or two. The property under test is that
    # the label never falls back to AWSCURRENT and ultimately 404s, so both are asserted -- every
    # read during the window must still be the stale v2, and the deadline must see the refusal.
    code, message = _await_stage_gone(sm, arn, "AWSPENDING", stale_version=v2)
    assert code == "ResourceNotFoundException", (
        "reading a staging label that no version holds must be refused, not fall back "
        f"to AWSCURRENT; got {code}"
    )
    expected = "Secrets Manager can't find the specified secret value for staging label: AWSPENDING"
    assert message == expected, f"expected {expected!r}, got {message!r}"
    # The unlabelled version is still addressable by id and still intact.
    assert (
        sm.get_secret_value(SecretId=arn, VersionId=v2)["SecretString"] == pending_value
    )

    # Re-attach, so the promotion below starts from the canonical rotation state.
    sm.update_secret_version_stage(
        SecretId=arn, VersionStage="AWSPENDING", MoveToVersionId=v2
    )
    reattached = _settled_stage_map(sm, arn, lambda m: m == _want_staged)
    assert reattached == _want_staged, (
        f"re-adding AWSPENDING must restore the pre-removal map exactly, got {reattached}"
    )

    # finishSecret: move AWSCURRENT from v1 to v2, naming the current holder.
    sm.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=v2,
        RemoveFromVersionId=v1,
    )
    promoted = _settled_stage_map(
        sm, arn,
        lambda m: "AWSCURRENT" in m.get(v2, frozenset()) and m.get(v1) == frozenset({"AWSPREVIOUS"}))
    assert "AWSCURRENT" in promoted.get(v2, frozenset()), (
        f"v2 must hold AWSCURRENT after promotion, got {promoted}"
    )
    # Whether a manual promotion consumes the AWSPENDING label is not pinned down, so only a subset
    # is required here.
    assert promoted.get(v2, frozenset()) <= frozenset({"AWSCURRENT", "AWSPENDING"}), (
        f"v2 may hold only AWSCURRENT (and possibly a not-yet-consumed AWSPENDING), got {promoted.get(v2)}"
    )
    assert promoted.get(v1) == frozenset({"AWSPREVIOUS"}), (
        "the demoted version must be exactly AWSPREVIOUS -- it must not keep "
        f"AWSCURRENT, got {promoted.get(v1)}"
    )
    assert sum(1 for lab in promoted.values() if "AWSCURRENT" in lab) == 1, (
        f"exactly one version may hold AWSCURRENT, map was {promoted}"
    )

    # GetSecretValue's staging-label resolution lags DescribeSecret by a second or two: straight
    # after the promotion a default read can still resolve v1 and AWSPREVIOUS can still 404.
    final_read = _read_stage(sm, arn, expect_version=v2)
    assert final_read["VersionId"] == v2, (
        f"after promotion the default read must resolve v2, got {final_read['VersionId']}"
    )
    assert final_read["SecretString"] == pending_value
    previous_read = _read_stage(sm, arn, stage="AWSPREVIOUS", expect_version=v1)
    assert previous_read["VersionId"] == v1, (
        f"AWSPREVIOUS must resolve the demoted v1, got {previous_read['VersionId']}"
    )
    assert previous_read["SecretString"] == current_value, (
        "the demoted version must still serve its original value under AWSPREVIOUS"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
