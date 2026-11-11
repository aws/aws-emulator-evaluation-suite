"""delete-secret-schedules-deletion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError was raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "delete-secret-schedules-deletion"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSecret (default recovery window) moves a secret to scheduled-for-deletion, not gone:
    retrieval is blocked while pending, and RestoreSecret proves the value was never destroyed."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name)

    # Positive control: the secret is readable before we break anything, so a later failure to
    # read it is attributable to the scheduled deletion and not to a broken fixture.
    initial = sm.get_secret_value(SecretId=name)
    assert initial.get("SecretString") == "initial-value", (
        f"positive control failed: expected SecretString 'initial-value', got {initial.get('SecretString')!r}"
    )

    del_resp = sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)
    assert "DeletionDate" in del_resp, f"DeleteSecret response missing DeletionDate: {del_resp}"

    desc = sm.describe_secret(SecretId=name)
    assert desc.get("DeletedDate") is not None, f"DescribeSecret did not report DeletedDate: {desc}"

    err = _error(lambda: sm.get_secret_value(SecretId=name))
    assert err.get("Code") == "InvalidRequestException", f"expected InvalidRequestException, got {err}"
    assert err.get("Message") == (
        "You can't perform this operation on the secret because it was marked for deletion."
    ), f"unexpected message for a read of a pending-deletion secret: {err.get('Message')!r}"

    # Restore: the only way to distinguish "scheduled for deletion" from "actually gone" is to
    # reverse it and get the original value back.
    sm.restore_secret(SecretId=name)

    restored_desc = sm.describe_secret(SecretId=name)
    assert restored_desc.get("DeletedDate") is None, (
        f"RestoreSecret did not clear DeletedDate: {restored_desc}"
    )

    restored = sm.get_secret_value(SecretId=name)
    assert restored.get("SecretString") == "initial-value", (
        f"restored secret value mismatch: expected 'initial-value', got {restored.get('SecretString')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
