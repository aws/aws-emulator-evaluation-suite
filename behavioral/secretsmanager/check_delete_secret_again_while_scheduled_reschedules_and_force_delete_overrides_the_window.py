"""delete-secret-again-while-scheduled-reschedules-and-force-delete-overrides-the-window."""
from __future__ import annotations

import datetime
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
    """Return the refused call's (Error.Code, Error.Message); an unexpected success raises."""
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


CHECK = "delete-secret-again-while-scheduled-reschedules-and-force-delete-overrides-the-window"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


def _whole_days(later, earlier):
    """The offset between two timestamps, in days, rounded to the nearest whole day."""
    return round((later - earlier) / datetime.timedelta(days=1))


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreSecret on an unscheduled secret is a no-op; a second DeleteSecret on a scheduled
    secret moves DeletionDate to the new window; a force delete then overrides it for good.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-resched-")
    created = _create_secret(sm, ctx, name, SecretString="sim2real-not-a-real-secret")

    noop = sm.restore_secret(SecretId=name)
    assert noop["ARN"] == created["ARN"], "RestoreSecret on an active secret must be accepted"
    assert sm.describe_secret(SecretId=name).get("DeletedDate") is None, (
        "a no-op restore must not mark the secret deleted"
    )
    assert sm.get_secret_value(SecretId=name)["VersionId"] == created["VersionId"], (
        "the secret must stay readable after a no-op restore"
    )

    first = sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)
    first_marked = sm.describe_secret(SecretId=name)["DeletedDate"]
    assert _whole_days(first["DeletionDate"], first_marked) == 7, (
        f"the first schedule must be 7 days out, got {first['DeletionDate'] - first_marked}"
    )

    second = sm.delete_secret(SecretId=name, RecoveryWindowInDays=12)
    assert second["ARN"] == created["ARN"], "a second DeleteSecret on a scheduled secret is accepted"
    second_marked = sm.describe_secret(SecretId=name)["DeletedDate"]
    assert second_marked >= first_marked, "the re-schedule cannot move DeletedDate backwards"
    assert _whole_days(second["DeletionDate"], second_marked) == 12, (
        f"the re-schedule must use the new 12-day window, got {second['DeletionDate'] - second_marked}"
    )
    assert second["DeletionDate"] > first["DeletionDate"], (
        "the longer window must move DeletionDate later than the first schedule"
    )

    code, message = _refusal(lambda: sm.get_secret_value(SecretId=name))
    assert code == "InvalidRequestException", f"a scheduled secret must not be readable, got {code!r}"
    assert message == (
        "You can't perform this operation on the secret because it was marked for deletion."
    ), f"unexpected read-while-scheduled message: {message!r}"

    forced = sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    assert forced["ARN"] == created["ARN"], "a force delete on a scheduled secret is accepted"
    assert forced["DeletionDate"] < second["DeletionDate"], (
        "the force delete must replace the pending window with an immediate deletion"
    )

    def gone():
        try:
            sm.describe_secret(SecretId=name)
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return None

    final = _poll(gone, lambda c: c == "ResourceNotFoundException", timeout_s=90.0)
    assert final == "ResourceNotFoundException", (
        f"a force-deleted secret must converge to not found, last observation {final!r}"
    )
    code, message = _refusal(lambda: sm.restore_secret(SecretId=name))
    assert code == "ResourceNotFoundException", f"a force-deleted secret cannot be restored, got {code!r}"
    assert message == "Secrets Manager can't find the specified secret.", (
        f"unexpected restore-after-force message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
