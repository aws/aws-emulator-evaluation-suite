"""get-secret-value-scheduled-deletion-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

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

_MARKED_FOR_DELETION_MESSAGE = (
    "You can't perform this operation on the secret because it was marked for deletion."
)
CHECK = "get-secret-value-scheduled-deletion-fails"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSecretValue on a secret scheduled for deletion must fail, not return stale data, and
    restoring the secret must make the identical call succeed again."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(
        sm, ctx, name=name, secret_string="secret-data",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    # Positive control: the secret is readable before anything is broken.
    before = sm.get_secret_value(SecretId=name)
    assert before["SecretString"] == "secret-data", (
        f"positive control failed: expected SecretString 'secret-data', got "
        f"{before.get('SecretString')!r}"
    )

    sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)

    code, message = _error_code(lambda: sm.get_secret_value(SecretId=name))
    assert code == "InvalidRequestException", (
        f"reading a secret pending deletion must be rejected, got {code}"
    )
    assert message == _MARKED_FOR_DELETION_MESSAGE, f"unexpected refusal message: {message!r}"

    sm.restore_secret(SecretId=name)

    after = sm.get_secret_value(SecretId=name)
    assert after["SecretString"] == "secret-data", (
        f"the identical call must succeed again after restore: expected SecretString "
        f"'secret-data', got {after.get('SecretString')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
