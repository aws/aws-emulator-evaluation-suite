"""rotate-secret-duration-without-a-schedule-or-frequency-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rotate-secret-duration-without-a-schedule-or-frequency-rejected"
GROUP = "error-semantics"
SERVICES = ["secretsmanager"]

_DURATION_MESSAGE = "You must provide a schedule expression or rotation frequency when using the duration option."
_NO_LAMBDA_MESSAGE = "No Lambda rotation function ARN is associated with this secret."


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """RotateSecret with RotationRules.Duration but no ScheduleExpression or AutomaticallyAfterDays
    is refused with InvalidParameterException before the missing-Lambda check, and leaves rotation,
    the version map and the secret value unchanged.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-durationonly-")

    original = "sim2real-not-a-real-secret-v1"
    created = sm.create_secret(
        Name=name, SecretString=original,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(lambda: _reap_secret(sm, arn))

    # No RotationLambdaARN either: if the Lambda-ARN check ran first, this would answer
    # _NO_LAMBDA_MESSAGE instead.
    code, message = _error_code(lambda: sm.rotate_secret(SecretId=arn, RotationRules={"Duration": "2h"}))
    assert code == "InvalidParameterException", (
        f"Duration with no schedule expression and no rotation frequency must be refused with "
        f"InvalidParameterException, got {code!r}"
    )
    assert message == _DURATION_MESSAGE, f"unexpected refusal message: {message!r}"

    desc = sm.describe_secret(SecretId=arn)
    assert not desc.get("RotationEnabled", False), (
        f"the refused call must not enable rotation; RotationEnabled={desc.get('RotationEnabled')!r}"
    )
    assert not desc.get("RotationRules"), f"the refused call must not persist RotationRules, got {desc.get('RotationRules')}"
    assert "NextRotationDate" not in desc, f"the refused call must not schedule one; keys were {sorted(desc)}"
    stage_map = desc["VersionIdsToStages"]
    assert set(stage_map) == {v1} and set(stage_map[v1]) == {"AWSCURRENT"}, (
        f"the version map must be unchanged at exactly v1=AWSCURRENT, got {stage_map}"
    )
    value = sm.get_secret_value(SecretId=arn)["SecretString"]
    assert value == original, f"the secret material must be untouched after the refusal, got {value!r}"

    # Control: Duration with AutomaticallyAfterDays clears the cross-field check and is refused only
    # for the missing Lambda ARN.
    code2, message2 = _error_code(
        lambda: sm.rotate_secret(SecretId=arn, RotationRules={"Duration": "2h", "AutomaticallyAfterDays": 30})
    )
    assert code2 == "InvalidRequestException", (
        f"Duration paired with AutomaticallyAfterDays must clear RotationRules validation and be "
        f"refused for a DIFFERENT reason (missing Lambda ARN), got {code2!r}"
    )
    assert message2 == _NO_LAMBDA_MESSAGE, f"unexpected refusal message: {message2!r}"

    # Control: the secret is not wedged; ordinary mutation still works.
    sm.update_secret(SecretId=arn, Description="sim2real behavioural control update")
    v2 = sm.put_secret_value(SecretId=arn, SecretString="sim2real-not-a-real-secret-v2")["VersionId"]
    assert v2 != v1, f"PutSecretValue after two refused RotateSecret calls did not mint a new version: {v2}"
    got2 = sm.get_secret_value(SecretId=arn)["VersionId"]
    assert got2 == v2, f"an independent read did not resolve the new version: {got2} != {v2}"


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _reap_secret(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
