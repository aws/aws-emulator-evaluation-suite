"""secret-binary-roundtrip-secretstring-absent."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ForceDeleteWithoutRecovery: DeleteSecret's minimum recovery window is 7 days and a
# secret pending deletion still bills.


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
                f"secret {secret_id} still present {timeout_s}s after "
                f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        **kwargs,
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _digest(blob):
    """Short digest for diagnostics -- never put secret material in an assert message."""
    return hashlib.sha256(blob).hexdigest()[:16]


CHECK = "secret-binary-roundtrip-secretstring-absent"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecretBinary secret round-trips byte-identically and its GetSecretValue omits SecretString.
    Callers tell string from binary versions by key presence, so the absent field is contract.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-binsecret-")

    # Self-labelling prefix + every byte value 0..255, so the payload is both
    # obviously synthetic and not valid UTF-8, so any lossy text conversion is caught.
    payload = b"sim2real-not-a-real-secret:" + bytes(range(256))

    created = _create_secret(sm, ctx, name, SecretBinary=payload)
    arn = created["ARN"]
    v1 = created["VersionId"]

    # Read only by the ARN this check minted -- never by a name it did not create.
    got1 = sm.get_secret_value(SecretId=arn)
    assert got1["ARN"] == arn, f"read resolved a different secret: {got1['ARN']} != {arn}"
    assert got1["VersionId"] == v1, f"expected version {v1}, got {got1['VersionId']}"
    assert got1["SecretBinary"] == payload, (
        "SecretBinary must round-trip byte-identically; "
        f"expected sha256:{_digest(payload)} len={len(payload)}, "
        f"got sha256:{_digest(got1['SecretBinary'])} len={len(got1['SecretBinary'])}"
    )
    assert "SecretString" not in got1, (
        "GetSecretValue on a binary-only version must OMIT SecretString, not return "
        f"an empty string; response keys were {sorted(got1)}"
    )

    # Now write a string version over the top: the fields must swap, not coexist.
    string_value = "sim2real-not-a-real-secret-v2"
    put = sm.put_secret_value(SecretId=arn, SecretString=string_value)
    v2 = put["VersionId"]
    assert v2 != v1, "PutSecretValue must mint a new version id"

    got2 = sm.get_secret_value(SecretId=arn)
    assert got2["VersionId"] == v2, f"AWSCURRENT must be {v2}, got {got2['VersionId']}"
    assert got2["SecretString"] == string_value, (
        f"expected SecretString {string_value!r}, got {got2.get('SecretString')!r}"
    )
    assert "SecretBinary" not in got2, (
        "a string-only version must OMIT SecretBinary; "
        f"response keys were {sorted(got2)}"
    )

    # The binary version is still readable by id, still byte-exact, still string-free.
    got_v1 = sm.get_secret_value(SecretId=arn, VersionId=v1)
    assert got_v1["SecretBinary"] == payload, (
        "the superseded binary version must remain byte-identical; "
        f"expected sha256:{_digest(payload)}, got sha256:{_digest(got_v1['SecretBinary'])}"
    )
    assert "SecretString" not in got_v1, f"response keys were {sorted(got_v1)}"

    # Exact staging map -- not a truthiness check.
    stages = sm.describe_secret(SecretId=arn)["VersionIdsToStages"]
    assert set(stages.get(v2, [])) == {"AWSCURRENT"}, (
        f"v2 must hold exactly AWSCURRENT, got {stages.get(v2)}"
    )
    assert set(stages.get(v1, [])) == {"AWSPREVIOUS"}, (
        f"v1 must hold exactly AWSPREVIOUS, got {stages.get(v1)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
