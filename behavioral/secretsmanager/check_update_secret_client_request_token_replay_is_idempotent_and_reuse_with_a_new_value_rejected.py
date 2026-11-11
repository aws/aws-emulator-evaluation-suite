"""update-secret-client-request-token-replay-is-idempotent-and-reuse-with-a-new-value-rejected."""
from __future__ import annotations

import time
import uuid

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
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises."""
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


CHECK = "update-secret-client-request-token-replay-is-idempotent-and-reuse-with-a-new-value-rejected"
GROUP = "idempotency"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSecret's ClientRequestToken becomes the version id; a same-value replay mints nothing
    and reuse with a new value is refused (ResourceExistsException), leaving AWSPREVIOUS intact.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-updtok-")
    created = _create_secret(sm, ctx, name, SecretString="v1")
    v1 = created["VersionId"]
    token = str(uuid.uuid4())

    first = sm.update_secret(SecretId=name, SecretString="v2", ClientRequestToken=token)
    assert first["VersionId"] == token, (
        "the ClientRequestToken becomes the new version id; got a different id of length "
        f"{len(first['VersionId'])}"
    )
    replay = sm.update_secret(SecretId=name, SecretString="v2", ClientRequestToken=token)
    assert replay["VersionId"] == token, "a replay with the same token must return the same version"

    def version_map():
        return {v["VersionId"]: sorted(v["VersionStages"])
                for v in sm.list_secret_version_ids(SecretId=name)["Versions"]}

    assert version_map() == {token: ["AWSCURRENT"], v1: ["AWSPREVIOUS"]}, (
        f"the replay must not mint a version: expected 2 versions, got {len(version_map())}"
    )

    code, message = _refusal(
        lambda: sm.update_secret(SecretId=name, SecretString="v3", ClientRequestToken=token))
    assert code == "ResourceExistsException", (
        f"reusing a token for a different value must be refused, got {code!r}"
    )
    assert message == (
        f"You can't use ClientRequestToken {token} because that value is already in use for a "
        f"version of secret {created['ARN']}."
    ), f"unexpected refusal message: {message!r}"

    current = sm.get_secret_value(SecretId=name)
    assert (current["VersionId"], current["SecretString"]) == (token, "v2"), (
        "the refused update must leave AWSCURRENT on the token version holding v2"
    )
    previous = sm.get_secret_value(SecretId=name, VersionStage="AWSPREVIOUS")
    assert (previous["VersionId"], previous["SecretString"]) == (v1, "v1"), (
        "the refused update and the replay must leave the original value in AWSPREVIOUS"
    )
    assert version_map() == {token: ["AWSCURRENT"], v1: ["AWSPREVIOUS"]}, (
        "the refused update must not add a version"
    )

    # The same token and value through PutSecretValue is the same idempotent request.
    put = sm.put_secret_value(SecretId=name, SecretString="v2", ClientRequestToken=token)
    assert put["VersionId"] == token, "PutSecretValue with the same token and value is a replay"
    assert version_map() == {token: ["AWSCURRENT"], v1: ["AWSPREVIOUS"]}, (
        "a cross-operation replay must not mint a version"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
