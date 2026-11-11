"""delete-secret-conflicting-recovery-params-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-secret-conflicting-recovery-params-rejected"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSecret rejects RecoveryWindowInDays+ForceDeleteWithoutRecovery together; a single-param call still works."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-delparams-secret-")
    created = sm.create_secret(
        Name=name, SecretString="delparams-value", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = created["ARN"]

    def _cleanup():
        try:
            sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Break exactly one thing: specify both mutually exclusive delete parameters.
    code, message = _refusal(
        lambda: sm.delete_secret(SecretId=arn, RecoveryWindowInDays=14, ForceDeleteWithoutRecovery=True)
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for conflicting delete params, got {code!r}"
    )
    assert message == "You can't use ForceDeleteWithoutRecovery in conjunction with RecoveryWindowInDays.", (
        f"unexpected refusal message: {message!r}"
    )

    # Effect absent: the secret is still fully active, not scheduled for deletion, value intact.
    described = sm.describe_secret(SecretId=arn)
    assert described.get("DeletedDate") is None, (
        f"expected no DeletedDate after rejected delete, got {described.get('DeletedDate')!r}"
    )
    value = sm.get_secret_value(SecretId=arn)
    assert value["SecretString"] == "delparams-value", (
        f"expected secret value intact after rejected delete, got {value['SecretString']!r}"
    )

    # Positive control: the same operation with a single valid parameter succeeds and takes effect.
    sm.delete_secret(SecretId=arn, RecoveryWindowInDays=7)
    described = sm.describe_secret(SecretId=arn)
    assert described.get("DeletedDate") is not None, (
        "expected DeletedDate to be set after a valid single-parameter delete, got None"
    )


def _refusal(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, so a target
    that accepts the conflicting parameters fails loudly instead of as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
