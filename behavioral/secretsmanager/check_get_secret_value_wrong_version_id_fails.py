"""get-secret-value-wrong-version-id-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

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

CHECK = "get-secret-value-wrong-version-id-fails"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSecretValue with a VersionId that doesn't belong to the secret raises ResourceNotFoundException."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    created = _create_secret(sm, ctx, name=name)
    v1 = created["VersionId"]
    bogus_version = "00000000-0000-0000-0000-000000000000"

    # Positive control: the real current version reads back fine. Without this, a
    # target that rejects every GetSecretValue call would pass this check too.
    before = sm.get_secret_value(SecretId=name)
    assert before["VersionId"] == v1, f"expected current version {v1}, got {before['VersionId']}"
    assert before["SecretString"] == "initial-value", (
        f"expected 'initial-value', got {before['SecretString']!r}"
    )

    code, message = _error_code(lambda: sm.get_secret_value(SecretId=name, VersionId=bogus_version))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Secrets Manager can't find the specified secret value for VersionId: {bogus_version}", f"unexpected not-found message: {message!r}"

    # Effect absent: the real version is still there, unmoved, unchanged -- the
    # failed read did not advance or corrupt state.
    after = sm.get_secret_value(SecretId=name)
    assert after["VersionId"] == v1, f"expected version to remain {v1}, got {after['VersionId']}"
    assert after["SecretString"] == "initial-value", (
        f"expected 'initial-value' after the failed read, got {after['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
