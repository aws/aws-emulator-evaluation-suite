"""delete-secret-recovery-window-out-of-range-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _refusal(fn):
    """Call fn() and return the botocore (Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

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

CHECK = "delete-secret-recovery-window-out-of-range-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSecret rejects a RecoveryWindowInDays outside [7, 30] on either side, leaving the secret
    untouched; a valid window on a sibling secret still succeeds (positive control)."""
    sm = ctx.client("secretsmanager")

    control_name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=control_name)
    control_resp = sm.delete_secret(SecretId=control_name, RecoveryWindowInDays=7)
    assert control_resp.get("DeletionDate") is not None, (
        f"positive control: DeleteSecret with a valid RecoveryWindowInDays=7 did not schedule "
        f"deletion: {control_resp!r}"
    )
    control_desc = sm.describe_secret(SecretId=control_name)
    assert control_desc.get("DeletedDate") is not None, (
        f"positive control: describe_secret shows no DeletedDate after a valid DeleteSecret "
        f"call: {control_desc!r}"
    )

    for bad_window in (1, 31):
        name = ctx.unique_name("sim2real-behav-secret-")
        _create_secret(sm, ctx, name=name)

        code, message = _refusal(
            lambda bad_window=bad_window: sm.delete_secret(
                SecretId=name, RecoveryWindowInDays=bad_window
            )
        )
        assert code == "InvalidParameterException", (
            f"RecoveryWindowInDays={bad_window} is outside [7, 30]: expected "
            f"InvalidParameterException, got {code!r}"
        )
        assert message == "The RecoveryWindowInDays value must be between 7 and 30 days (inclusive).", (
            f"RecoveryWindowInDays={bad_window}: unexpected refusal message {message!r}"
        )

        desc = sm.describe_secret(SecretId=name)
        assert desc.get("DeletedDate") is None, (
            f"a rejected DeleteSecret(RecoveryWindowInDays={bad_window}) still scheduled "
            f"{name!r} for deletion: {desc!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
