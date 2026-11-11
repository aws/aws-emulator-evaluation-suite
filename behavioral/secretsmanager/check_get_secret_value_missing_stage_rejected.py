"""get-secret-value-missing-stage-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError was raised. An unexpected SUCCESS
    raises rather than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )

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

def _await_stage_resolves(sm, secret_id, stage, expect_version, *, timeout_s=30.0, interval_s=2.0):
    """GetSecretValue for ``stage`` once it resolves ``expect_version``.

    Measured on real AWS: GetSecretValue's staging-label index lags PutSecretValue by a second or
    two, so an immediate read can still see a ResourceNotFoundException or the pre-attach state.
    This only defers the assertion until the label catches up; a label that never resolves still
    raises.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            got = sm.get_secret_value(SecretId=secret_id, VersionStage=stage)
            if got["VersionId"] == expect_version:
                return got
            last = got["VersionId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            last = "ResourceNotFoundException"
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{stage} never resolved {expect_version} within {timeout_s}s; last saw {last!r}"
            )
        time.sleep(interval_s)

CHECK = "get-secret-value-missing-stage-rejected"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSecretValue for a staging label that holds no version must fail, not fall back to
    AWSCURRENT -- and once the label is genuinely attached, the identical call must succeed."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name, secret_string="only-current")

    # positive control: the default (AWSCURRENT) read works before any negative is exercised
    assert sm.get_secret_value(SecretId=name)["SecretString"] == "only-current"

    for stage, kind in (("AWSPENDING", "unpopulated"), ("NOSUCHSTAGE", "unknown")):
        err = _error(lambda: sm.get_secret_value(SecretId=name, VersionStage=stage))
        assert err.get("Code") == "ResourceNotFoundException", (
            f"requesting an {kind} staging label must fail, got {err}"
        )
        expected_message = (
            f"Secrets Manager can't find the specified secret value for staging label: {stage}"
        )
        assert err.get("Message") == expected_message, (
            f"expected message {expected_message!r}, got {err.get('Message')!r}"
        )

    # restore: attach AWSPENDING to a new version without moving AWSCURRENT (the documented
    # rotation staging protocol), then demand the identical call that was just rejected now
    # succeeds against the version it was just attached to
    pending = sm.put_secret_value(
        SecretId=name, SecretString="pending-value", VersionStages=["AWSPENDING"]
    )
    resolved = _await_stage_resolves(sm, name, "AWSPENDING", pending["VersionId"])
    assert resolved["SecretString"] == "pending-value", (
        f"AWSPENDING now holds a version and must resolve to it, got "
        f"{resolved['SecretString']!r}"
    )

    # AWSCURRENT must be untouched by attaching a different stage to a different version
    assert sm.get_secret_value(SecretId=name)["SecretString"] == "only-current"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
