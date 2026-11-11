"""events-connection-api-key-is-stored-in-secrets-manager-and-rotated."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-connection-api-key-is-stored-in-secrets-manager-and-rotated"

GROUP = "cross-service"

SERVICES = ["events", "secretsmanager"]


@tags("axis:happy-path", "concern:e2e", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A Connection's API key lives in an events-owned secret, is never echoed by
    DescribeConnection, and UpdateConnection rotates the same secret to a new version holding
    the new key.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-target-connection.html
    """
    events = ctx.client("events")
    secrets = ctx.client("secretsmanager")

    key_name = "x-sim2real-api-key"
    key_v1 = _xname(ctx, "keyv1")
    key_v2 = _xname(ctx, "keyv2")
    assert key_v1 != key_v2, "the two key values must differ or the rotation assertion is vacuous"

    name = _xname(ctx, "conn")
    events.create_connection(
        Name=name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": key_name, "ApiKeyValue": key_v1}
        },
    )
    ctx.on_cleanup(
        lambda: _quiet(lambda: ctx.client("events").delete_connection(Name=name))
    )

    described = _poll_until(
        lambda: events.describe_connection(Name=name),
        lambda d: d.get("ConnectionState") in ("AUTHORIZED", "AUTHORIZING", "DEAUTHORIZED"),
        timeout_s=180.0,
        interval_s=3.0,
        description=f"connection {name} settled out of CREATING",
    )
    described = _poll_until(
        lambda: events.describe_connection(Name=name),
        lambda d: d.get("ConnectionState") == "AUTHORIZED",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"connection {name} reached AUTHORIZED",
    )
    assert described["ConnectionState"] == "AUTHORIZED", (
        f"connection {name} settled at ConnectionState={described['ConnectionState']!r}, expected "
        f"'AUTHORIZED'"
    )

    secret_arn = described.get("SecretArn")
    assert secret_arn, (
        f"DescribeConnection returned no SecretArn, so the key is not claimed to live in Secrets "
        f"Manager at all: {_redact(described, (key_v1, key_v2))!r}"
    )
    parts = secret_arn.split(":")
    assert len(parts) >= 6 and parts[0] == "arn" and parts[2] == "secretsmanager", (
        f"the connection's SecretArn is not a Secrets Manager ARN: {secret_arn!r} (service field "
        f"parsed as {parts[2] if len(parts) > 2 else None!r})"
    )

    # The control API must NOT hand the credential back. Serialise the WHOLE response, so a key
    # echoed anywhere in it -- including a field this check does not name -- is caught.
    serialised = json.dumps(described, default=str)
    assert key_v1 not in serialised, (
        f"DescribeConnection echoed the configured API key value back through the control plane "
        f"(sha256 {_h(key_v1)}); AuthParameters were "
        f"{_redact(described.get('AuthParameters'), (key_v1, key_v2))!r}"
    )
    auth = described.get("AuthParameters") or {}
    assert "ApiKeyAuthParameters" in auth and "ApiKeyName" in auth["ApiKeyAuthParameters"], (
        f"DescribeConnection did not report the API key NAME it was given: AuthParameters="
        f"{auth!r}"
    )
    assert auth["ApiKeyAuthParameters"]["ApiKeyName"] == key_name, (
        f"DescribeConnection reported ApiKeyName="
        f"{auth['ApiKeyAuthParameters']['ApiKeyName']!r}, expected {key_name!r}"
    )
    assert "ApiKeyValue" not in auth["ApiKeyAuthParameters"], (
        f"DescribeConnection returned an ApiKeyValue field, which is the credential-leak shape this "
        f"check exists to catch: {sorted(auth['ApiKeyAuthParameters'].keys())!r}"
    )

    stored = json.loads(_get_secret_string(secrets, secret_arn))
    assert sorted(stored.keys()) == ["api_key_name", "api_key_value"], (
        f"the connection's secret does not carry the documented shape: keys were "
        f"{sorted(stored.keys())!r}, expected ['api_key_name', 'api_key_value']"
    )
    assert stored["api_key_name"] == key_name, (
        f"the stored api_key_name is {stored['api_key_name']!r}, expected {key_name!r}"
    )
    assert _h(stored["api_key_value"]) == _h(key_v1), (
        f"the secret at {secret_arn} does not hold the key that was configured: stored sha256 "
        f"{_h(stored['api_key_value'])}, configured sha256 {_h(key_v1)}"
    )

    meta = secrets.describe_secret(SecretId=secret_arn)
    assert meta.get("OwningService") == "events", (
        f"the connection's secret is not marked as owned by EventBridge: OwningService="
        f"{meta.get('OwningService')!r}. A secret the caller owns is one the caller can rewrite "
        f"behind the connection's back"
    )
    versions_before = sorted((meta.get("VersionIdsToStages") or {}).keys())
    assert len(versions_before) == 1, (
        f"a freshly created connection's secret should carry exactly one version, got "
        f"{len(versions_before)}: {versions_before!r}"
    )

    # Rotate: one call, one thing changed -- the key value.
    events.update_connection(
        Name=name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": key_name, "ApiKeyValue": key_v2}
        },
    )
    rotated = _poll_until(
        lambda: events.describe_connection(Name=name),
        lambda d: d.get("ConnectionState") == "AUTHORIZED",
        timeout_s=240.0,
        interval_s=3.0,
        description=f"connection {name} back to AUTHORIZED after UpdateConnection",
    )
    assert rotated.get("SecretArn") == secret_arn, (
        f"UpdateConnection moved the credential to a different secret ({rotated.get('SecretArn')!r} "
        f"was {secret_arn!r}), which orphans the old one instead of rotating it"
    )

    after = _poll_until(
        lambda: json.loads(_get_secret_string(secrets, secret_arn)),
        lambda s: _h(s.get("api_key_value", "")) == _h(key_v2),
        timeout_s=120.0,
        interval_s=3.0,
        description=f"secret {secret_arn} advanced to the rotated key (sha256 {_h(key_v2)})",
    )
    assert _h(after["api_key_value"]) == _h(key_v2), (
        f"after UpdateConnection the secret still does not hold the new key: stored sha256 "
        f"{_h(after['api_key_value'])}, expected {_h(key_v2)}"
    )
    assert _h(after["api_key_value"]) != _h(key_v1), (
        f"the secret still holds the ORIGINAL key after the rotation (sha256 {_h(key_v1)})"
    )

    meta_after = secrets.describe_secret(SecretId=secret_arn)
    versions_after = sorted((meta_after.get("VersionIdsToStages") or {}).keys())
    assert len(versions_after) >= 2, (
        f"the rotation did not create a new secret VERSION: {len(versions_after)} version(s) "
        f"{versions_after!r}, was {versions_before!r}. Overwriting in place loses the previous "
        f"credential and is not what real Secrets Manager does here"
    )
    assert set(versions_before).issubset(set(versions_after)), (
        f"the pre-rotation version disappeared: before {versions_before!r}, after "
        f"{versions_after!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _h(value: str) -> str:
    """A short sha256 digest, so a failure message can name a credential without printing one."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _redact(obj: Any, secrets: tuple[str, ...]) -> str:
    """Serialise a response with every known key value replaced by its digest."""
    text = json.dumps(obj, default=str)
    for s in secrets:
        text = text.replace(s, f"<redacted sha256 {_h(s)}>")
    return text


def _quiet(fn) -> None:
    """Teardown helper: a delete that races another delete must not mask a verdict."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get_secret_string(secrets, secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    value = resp.get("SecretString")
    assert value, (
        f"GetSecretValue on {secret_id!r} returned no SecretString (keys "
        f"{sorted(resp.keys())!r}), so the credential is not readable where EventBridge says it is"
    )
    return value


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy and return it; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
