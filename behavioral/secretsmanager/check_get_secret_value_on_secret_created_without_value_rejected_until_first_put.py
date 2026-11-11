"""get-secret-value-on-secret-created-without-value-rejected-until-first-put."""
from __future__ import annotations

import time

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
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises,
    so accepting what AWS refuses is named rather than read as a mismatch."""
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


CHECK = "get-secret-value-on-secret-created-without-value-rejected-until-first-put"
GROUP = "data-plane"
SERVICES = ["secretsmanager"]

_NO_CURRENT = "Secrets Manager can't find the specified secret value for staging label: AWSCURRENT"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A secret created without a value has no version: GetSecretValue (name, ARN) and its
    BatchGetSecretValue entry are refused with ResourceNotFoundException naming AWSCURRENT until
    the first PutSecretValue mints the one and only version.
    """
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-novalue-")
    empty_name = f"{base}-empty"
    control_name = f"{base}-control"

    created = _create_secret(sm, ctx, empty_name)
    assert "VersionId" not in created, (
        f"CreateSecret with no value must not mint a version, response keys {sorted(created)}"
    )
    control = _create_secret(sm, ctx, control_name, SecretString="sim2real-not-a-real-secret")

    for label, secret_id in (("name", empty_name), ("ARN", created["ARN"])):
        code, message = _refusal(lambda secret_id=secret_id: sm.get_secret_value(SecretId=secret_id))
        assert code == "ResourceNotFoundException", (
            f"GetSecretValue by {label} on a valueless secret must be refused, got {code!r}"
        )
        assert message == _NO_CURRENT, f"unexpected message by {label}: {message!r}"

    desc = sm.describe_secret(SecretId=empty_name)
    assert desc["ARN"] == created["ARN"], "DescribeSecret must still serve the valueless secret"
    assert not desc.get("VersionIdsToStages"), (
        f"a valueless secret has no versions, DescribeSecret reported {desc.get('VersionIdsToStages')!r}"
    )
    versions = sm.list_secret_version_ids(SecretId=empty_name)["Versions"]
    assert versions == [], f"ListSecretVersionIds must be empty, got {len(versions)} version(s)"

    batch = sm.batch_get_secret_value(SecretIdList=[empty_name, control["ARN"]])
    served = [e["Name"] for e in batch["SecretValues"]]
    assert served == [control_name], (
        f"the batch must serve only the secret that has a value, served {served}"
    )
    errors = [(e["SecretId"], e["ErrorCode"], e["Message"]) for e in batch.get("Errors", [])]
    assert errors == [(empty_name, "ResourceNotFoundException", _NO_CURRENT)], (
        f"the valueless secret must appear as one per-secret error, got {errors}"
    )

    put = sm.put_secret_value(SecretId=empty_name, SecretString="first-value")
    assert put["VersionStages"] == ["AWSCURRENT"], (
        f"the first PutSecretValue must label its version AWSCURRENT, got {put['VersionStages']!r}"
    )
    got = sm.get_secret_value(SecretId=empty_name)
    assert got["VersionId"] == put["VersionId"], "GetSecretValue must serve the first version"
    assert got["SecretString"] == "first-value", "GetSecretValue must serve the first value"

    described = _poll(lambda: sm.describe_secret(SecretId=empty_name),
                      lambda d: bool(d.get("VersionIdsToStages")), timeout_s=60.0, interval_s=2.0)
    stages = described.get("VersionIdsToStages", {})
    assert stages == {put["VersionId"]: ["AWSCURRENT"]}, (
        f"after the first put there is exactly one version, AWSCURRENT; got {len(stages)} "
        f"version(s) with stages {sorted(map(tuple, stages.values()))}"
    )
    code, message = _refusal(
        lambda: sm.get_secret_value(SecretId=empty_name, VersionStage="AWSPREVIOUS"))
    assert code == "ResourceNotFoundException", (
        f"there is no AWSPREVIOUS after the first put, got {code!r}"
    )
    assert message == (
        "Secrets Manager can't find the specified secret value for staging label: AWSPREVIOUS"
    ), f"unexpected AWSPREVIOUS message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
