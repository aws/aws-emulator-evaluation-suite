"""describe-nonexistent-secret-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

CHECK = "describe-nonexistent-secret-fails"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSecret on a SecretId that was never created raises ResourceNotFoundException,
    while an identical call against a real, just-created secret succeeds (positive control)."""
    sm = ctx.client("secretsmanager")

    control_name = ctx.unique_name("sim2real-behav-control-")
    control_arn = sm.create_secret(
        Name=control_name,
        SecretString="control-value",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=control_name, ForceDeleteWithoutRecovery=True)
    )
    control = sm.describe_secret(SecretId=control_name)
    assert control["ARN"] == control_arn, f"expected {control_arn}, got {control['ARN']}"

    missing = ctx.unique_name("sim2real-behav-missing-")
    err = _error(lambda: sm.describe_secret(SecretId=missing))
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    assert err.get("Message") == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message: {err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
