"""put-secret-value-token-conflict-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "put-secret-value-token-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises, naming what actually happened."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - deliberately broad, we only want the code
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(
        f"expected ResourceExistsException, but the call SUCCEEDED and returned {result!r}"
    )


def _token_in_use_message(token: str, secret_arn: str) -> str:
    """The ResourceExistsException message for a ClientRequestToken reused with other content."""
    return (
        f"You can't use ClientRequestToken {token} because that value is already in use for a "
        f"version of secret {secret_arn}."
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with DIFFERENT content on PutSecretValue is rejected
    with ResourceExistsException, the current version is left untouched, and a fresh
    token still succeeds (positive control in the same file)."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-")

    arn = sm.create_secret(
        Name=name,
        SecretString="v1",
        Tags=[{"Key": "sim2real", "Value": "put-secret-value-token-conflict-rejected"}],
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    reused_token = str(uuid.uuid4())
    v2_resp = sm.put_secret_value(SecretId=name, ClientRequestToken=reused_token, SecretString="v2")
    v2_version_id = v2_resp["VersionId"]

    # Confirm v2 is now AWSCURRENT before attempting the conflicting reuse.
    v2_current = sm.get_secret_value(SecretId=name)
    assert v2_current["SecretString"] == "v2", (
        f"expected AWSCURRENT to hold 'v2' before the conflicting reuse, got {v2_current['SecretString']!r}"
    )
    assert v2_current["VersionId"] == v2_version_id, (
        f"expected AWSCURRENT VersionId {v2_version_id!r}, got {v2_current['VersionId']!r}"
    )

    # Break exactly one thing: reuse the SAME token with DIFFERENT content.
    code, message = _error_code(
        lambda: sm.put_secret_value(
            SecretId=name, ClientRequestToken=reused_token, SecretString="v2-conflicting"
        )
    )
    assert code == "ResourceExistsException", f"expected ResourceExistsException, got {code!r}"
    assert message == _token_in_use_message(reused_token, arn), f"unexpected conflict message: {message!r}"

    # Effect absent: the current value AND version are still v2's, not a minted v2-conflicting.
    after_conflict = sm.get_secret_value(SecretId=name)
    assert after_conflict["SecretString"] == "v2", (
        f"the rejected write changed AWSCURRENT's content: expected 'v2', got {after_conflict['SecretString']!r}"
    )
    assert after_conflict["VersionId"] == v2_version_id, (
        f"the rejected write minted a new version: expected {v2_version_id!r}, got {after_conflict['VersionId']!r}"
    )

    # Positive control: a fresh token with new content succeeds normally.
    fresh_token = str(uuid.uuid4())
    fresh_resp = sm.put_secret_value(SecretId=name, ClientRequestToken=fresh_token, SecretString="v3")
    assert fresh_resp["VersionId"] != v2_version_id, (
        f"positive control: a fresh token must mint a new version, got the existing {v2_version_id!r}"
    )
    after_fresh = sm.get_secret_value(SecretId=name)
    assert after_fresh["SecretString"] == "v3", (
        f"positive control: expected AWSCURRENT to hold 'v3', got {after_fresh['SecretString']!r}"
    )
    assert after_fresh["VersionId"] == fresh_resp["VersionId"], (
        f"positive control: expected AWSCURRENT VersionId {fresh_resp['VersionId']!r}, got {after_fresh['VersionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
