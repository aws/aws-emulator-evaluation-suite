"""create-duplicate-secret-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _refusal(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises."""
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

CHECK = "create-duplicate-secret-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSecret with a name already in use must raise ResourceExistsException, not overwrite."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name, secret_string="original")

    code, message = _refusal(
        lambda: sm.create_secret(Name=name, SecretString="different-content")
    )
    assert code == "ResourceExistsException", f"expected ResourceExistsException, got {code}"
    expected_message = f"The operation failed because the secret {name} already exists."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the rejected duplicate must not have overwritten the original value.
    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "original", (
        f"expected original secret value to survive the rejected duplicate create, "
        f"got {val['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
