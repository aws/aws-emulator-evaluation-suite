"""get-secret-value-nonexistent-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED: {result!r}")

CHECK = "get-secret-value-nonexistent-fails"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSecretValue on a SecretId that was never created raises ResourceNotFoundException.

    A positive control (a real, just-created secret) proves GetSecretValue works at all in this
    account/region, so the negative below cannot pass merely because every call is refused.
    """
    sm = ctx.client("secretsmanager")

    control_name = ctx.unique_name("sim2real-behav-control-")
    sm.create_secret(
        Name=control_name,
        SecretString="sim2real-control-value",
        Tags=[{"Key": "sim2real-behavioral", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _force_delete(sm, control_name))
    control = sm.get_secret_value(SecretId=control_name)
    assert control["SecretString"] == "sim2real-control-value", (
        f"positive control failed: expected the just-created secret to read back, got {control!r}"
    )

    missing = ctx.unique_name("sim2real-behav-missing-")
    err = _client_error(lambda: sm.get_secret_value(SecretId=missing))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    assert err.get("Message") == "Secrets Manager can't find the specified secret.", (
        f"unexpected ResourceNotFoundException message: {err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
