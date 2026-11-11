"""put-secret-value-on-deleted-secret-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message, HTTP status) if a ClientError was raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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

CHECK = "put-secret-value-on-deleted-secret-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSecretValue must be rejected on a secret that is scheduled for deletion."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name)

    # Positive control: the identical call succeeds against the live secret before it is broken.
    sm.put_secret_value(SecretId=name, SecretString="v2")

    sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)

    code, message, status = _error_code(lambda: sm.put_secret_value(SecretId=name, SecretString="sneaky"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert status == 400, f"expected HTTP 400 for the refusal, got {status!r}"
    expected_message = "You can't perform this operation on the secret because it was marked for deletion."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Restore, then prove the rejected write never applied and that the identical call now succeeds.
    sm.restore_secret(SecretId=name)
    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "v2", (
        f"PutSecretValue on a pending-deletion secret must not have applied, "
        f"got {val['SecretString']!r}"
    )

    sm.put_secret_value(SecretId=name, SecretString="v3")
    val2 = sm.get_secret_value(SecretId=name)
    assert val2["SecretString"] == "v3", (
        f"identical PutSecretValue must succeed once the secret is restored, "
        f"got {val2['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
