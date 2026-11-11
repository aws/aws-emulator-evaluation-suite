"""rotation-rules-validation-rejected."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ForceDeleteWithoutRecovery: a secret in its recovery window (minimum 7 days) still bills.


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
    resp = sm.create_secret(Name=name, **kwargs)
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _digest(text):
    """Short digest for diagnostics -- never put secret material in an assert message."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


CHECK = "rotation-rules-validation-rejected"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Each RotationRules field violation is refused with ValidationException and its exact message,
    and leaves no rotation flag, rules, schedule, Lambda, or new version behind.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_RotationRulesType.html
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-rotrules-")

    original = "sim2real-not-a-real-secret-v1"
    created = _create_secret(
        sm, ctx, name, SecretString=original,
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = created["ARN"]
    v1 = created["VersionId"]

    # Positive control: well-formed RotationRules without a Lambda ARN clears field validation and
    # is refused for the missing function instead, so validation runs before Lambda resolution.
    control_code, control_message = _error_code(
        lambda: sm.rotate_secret(SecretId=arn, RotationRules={"AutomaticallyAfterDays": 30})
    )
    assert control_code == "InvalidRequestException", (
        "a well-formed RotationRules with no rotation function configured must be refused "
        f"for a different reason than RotationRules validation, got {control_code!r}"
    )
    assert control_message == "No Lambda rotation function ARN is associated with this secret.", (
        f"unexpected control refusal message: {control_message!r}"
    )

    # Break exactly one field per case; botocore does not validate these patterns or ranges.
    prefix = "1 validation error detected: Value "
    cases = [
        ("Duration pattern (^[0-9]+h$)", {"Duration": "1x"},
         prefix + "'1x' at 'rotationRules.duration' failed to satisfy constraint: "
         "Member must satisfy regular expression pattern: [0-9]+h"),
        ("Duration length max 3", {"Duration": "1000h"},
         prefix + "'1000h' at 'rotationRules.duration' failed to satisfy constraint: "
         "Member must have length less than or equal to 3"),
        ("AutomaticallyAfterDays range max 1000", {"AutomaticallyAfterDays": 5000},
         prefix + "'5000' at 'rotationRules.automaticallyAfterDays' failed to satisfy constraint: "
         "Member must have value less than or equal to 1000"),
        ("ScheduleExpression charset", {"ScheduleExpression": "rate(30 days)!!"},
         prefix + "'rate(30 days)!!' at 'rotationRules.scheduleExpression' failed to satisfy "
         "constraint: Member must satisfy regular expression pattern: [0-9A-Za-z\\(\\)#\\?\\*\\-\\/, ]+"),
    ]
    for label, rules, expected_message in cases:
        code, message = _error_code(lambda r=rules: sm.rotate_secret(SecretId=arn, RotationRules=r))
        assert code == "ValidationException", (
            f"RotationRules violating {label} must be refused with ValidationException, "
            f"got {code} for {rules}"
        )
        assert message == expected_message, (
            f"RotationRules violating {label}: expected {expected_message!r}, got {message!r}"
        )

    # Effect absent, five ways: no rotation flag, no persisted rules, no schedule,
    # no new version, and the secret material untouched.
    desc = sm.describe_secret(SecretId=arn)
    assert not desc.get("RotationEnabled", False), (
        f"no refused call may enable rotation; RotationEnabled={desc.get('RotationEnabled')!r}"
    )
    assert not desc.get("RotationRules") or not any(
        desc["RotationRules"].get(k)
        for k in ("AutomaticallyAfterDays", "Duration", "ScheduleExpression")
    ), (
        f"no refused RotationRules may be persisted, got {desc.get('RotationRules')}"
    )
    assert "NextRotationDate" not in desc, (
        f"a refused rotation must not schedule one; response keys were {sorted(desc)}"
    )
    assert "RotationLambdaARN" not in desc, (
        f"no rotation function may be associated; response keys were {sorted(desc)}"
    )
    stage_map = desc["VersionIdsToStages"]
    assert set(stage_map) == {v1} and set(stage_map[v1]) == {"AWSCURRENT"}, (
        f"the version map must be unchanged at exactly v1=AWSCURRENT, got {stage_map}"
    )

    got = sm.get_secret_value(SecretId=arn)
    assert got["ARN"] == arn, f"read resolved a different secret: {got['ARN']} != {arn}"
    assert got["VersionId"] == v1, (
        f"four refused rotation calls must not move AWSCURRENT: {got['VersionId']} != {v1}"
    )
    assert _digest(got["SecretString"]) == _digest(original), (
        "the secret material must be byte-identical after four refused rotation calls; "
        f"sha256 {_digest(got['SecretString'])} != {_digest(original)}"
    )

    # Control: the secret is not wedged -- ordinary mutation still works.
    sm.update_secret(SecretId=arn, Description="sim2real behavioural control update")
    # DescribeSecret can lag UpdateSecret by a few seconds; bounded wait, then assert.
    deadline = time.monotonic() + 30.0
    updated_desc = sm.describe_secret(SecretId=arn).get("Description")
    while updated_desc != "sim2real behavioural control update" and time.monotonic() < deadline:
        time.sleep(2.0)
        updated_desc = sm.describe_secret(SecretId=arn).get("Description")
    assert updated_desc == "sim2real behavioural control update", (
        f"the secret is wedged after four refused rotations: UpdateSecret did not take, "
        f"Description={updated_desc!r}"
    )
    v2 = sm.put_secret_value(
        SecretId=arn, SecretString="sim2real-not-a-real-secret-v2"
    )["VersionId"]
    assert v2 != v1, f"PutSecretValue after four refused rotations did not mint a new version: {v2}"
    got2 = sm.get_secret_value(SecretId=arn)["VersionId"]
    assert got2 == v2, f"an independent read did not resolve the new version: {got2} != {v2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
