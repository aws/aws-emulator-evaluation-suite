"""update-secret-on-deleted-secret-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _current_version_id(sm, secret_id):
    """The version id currently staged AWSCURRENT, via DescribeSecret (readable even while
    the secret is scheduled for deletion, unlike GetSecretValue)."""
    desc = sm.describe_secret(SecretId=secret_id)
    for version_id, stages in desc.get("VersionIdsToStages", {}).items():
        if "AWSCURRENT" in stages:
            return version_id
    return None

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

CHECK = "update-secret-on-deleted-secret-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """UpdateSecret must be rejected on a secret that is scheduled for deletion, and the
    identical call must succeed again once the secret is restored."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name, secret_string="v1")

    # Positive control: UpdateSecret works on a live secret, proven by an independent read.
    sm.update_secret(SecretId=name, SecretString="v2-live")
    live = sm.get_secret_value(SecretId=name)
    assert live["SecretString"] == "v2-live", (
        f"expected live UpdateSecret to apply, got {live['SecretString']!r}"
    )
    live_version_id = _current_version_id(sm, name)

    sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)

    code, message = _error_code(lambda: sm.update_secret(SecretId=name, SecretString="sneaky"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == (
        "You can't perform this operation on the secret because it was marked for deletion."
    ), f"unexpected refusal message: {message!r}"

    # Effect absent while still scheduled for deletion: the rejected update never created a
    # new version. GetSecretValue itself is refused once a secret is marked for deletion
    # (confirmed on real AWS), so the independent read has to be DescribeSecret instead.
    blocked_version_id = _current_version_id(sm, name)
    assert blocked_version_id == live_version_id, (
        f"expected AWSCURRENT to stay {live_version_id!r} while scheduled for deletion, "
        f"got {blocked_version_id!r}"
    )

    sm.restore_secret(SecretId=name)

    # Restored: the identical call now succeeds.
    sm.update_secret(SecretId=name, SecretString="sneaky")
    restored = sm.get_secret_value(SecretId=name)
    assert restored["SecretString"] == "sneaky", (
        f"expected UpdateSecret to apply post-restore, got {restored['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
