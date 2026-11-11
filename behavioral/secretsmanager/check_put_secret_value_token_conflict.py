"""put-secret-value-token-conflict."""
from __future__ import annotations

import uuid

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


def _token_in_use_message(token: str, secret_arn: str) -> str:
    """The ResourceExistsException message for a ClientRequestToken reused with other content."""
    return (
        f"You can't use ClientRequestToken {token} because that value is already in use for a "
        f"version of secret {secret_arn}."
    )

CHECK = "put-secret-value-token-conflict"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSecretValue reusing a ClientRequestToken with different content conflicts; the
    conflict leaves AWSCURRENT untouched, and reusing the same token with its ORIGINAL content
    afterward is still an idempotent no-op, not a second conflict."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    arn = _create_secret(sm, ctx, name=name, secret_string="v1")["ARN"]

    token = uuid.uuid4().hex
    put_v2 = sm.put_secret_value(SecretId=name, SecretString="v2", ClientRequestToken=token)

    # Positive control via an independent read: the mutating call's own response is not enough.
    current = sm.get_secret_value(SecretId=name)
    assert current["SecretString"] == "v2" and current["VersionId"] == put_v2["VersionId"], (
        f"baseline write must be visible as AWSCURRENT before the conflicting reuse, "
        f"got {current['SecretString']!r}/{current['VersionId']!r}"
    )

    code, message = _error_code(
        lambda: sm.put_secret_value(
            SecretId=name, SecretString="different-content", ClientRequestToken=token
        )
    )
    assert code == "ResourceExistsException", (
        f"reusing a token with different content must conflict, got {code}"
    )
    assert message == _token_in_use_message(token, arn), f"unexpected conflict message: {message!r}"

    # Effect absent: an independent read, not the refused call's own (absent) response.
    after_conflict = sm.get_secret_value(SecretId=name)
    assert (
        after_conflict["SecretString"] == "v2" and after_conflict["VersionId"] == put_v2["VersionId"]
    ), (
        f"the rejected write must not change AWSCURRENT, but it now reads "
        f"{after_conflict['SecretString']!r}/{after_conflict['VersionId']!r}"
    )

    # Restore: the SAME token with its ORIGINAL content is an idempotent replay, not a second
    # conflict -- the conflict is specific to a content mismatch, not to token reuse itself.
    replay = sm.put_secret_value(SecretId=name, SecretString="v2", ClientRequestToken=token)
    assert replay["VersionId"] == put_v2["VersionId"], (
        f"replaying the same token with its original content must be idempotent, "
        f"got {replay['VersionId']!r} != {put_v2['VersionId']!r}"
    )
    after_replay = sm.get_secret_value(SecretId=name)
    assert (
        after_replay["SecretString"] == "v2" and after_replay["VersionId"] == put_v2["VersionId"]
    ), (
        f"the idempotent replay must leave AWSCURRENT unchanged, got "
        f"{after_replay['SecretString']!r}/{after_replay['VersionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
