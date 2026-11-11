"""create-secret-name-scheduled-for-deletion-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _refusal(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")

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

CHECK = "create-secret-name-scheduled-for-deletion-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSecret with the name of a secret scheduled for deletion is refused with
    InvalidRequestException (exact message) while the original stays scheduled; RestoreSecret then clears
    its DeletedDate and it holds "original".
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name, secret_string="original",
                    Tags=[{"Key": "sim2real", "Value": CHECK}])
    sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)

    code, message = _refusal(lambda: sm.create_secret(Name=name, SecretString="usurper"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == (
        "You can't create this secret because a secret with this name is already scheduled for deletion."
    ), f"unexpected refusal message: {message!r}"

    # Effect absent, via an independent read: the rejected create did not clear the
    # deletion schedule. (GetSecretValue itself refuses while a secret is scheduled for
    # deletion, so describe_secret is the only reachable read at this point.)
    described = sm.describe_secret(SecretId=name)
    assert described.get("DeletedDate") is not None, (
        f"expected DeletedDate to still be set after the rejected create, got "
        f"{described.get('DeletedDate')!r}"
    )

    # Restore: the scheduled-for-deletion secret is still fully recoverable with its
    # original value, so the rejected create did not corrupt or discard it.
    sm.restore_secret(SecretId=name)
    described = sm.describe_secret(SecretId=name)
    assert described.get("DeletedDate") is None, (
        f"expected DeletedDate to be cleared after restore_secret, got "
        f"{described.get('DeletedDate')!r}"
    )
    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "original", (
        f"expected the restored secret's value to still be 'original', got "
        f"{val['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
