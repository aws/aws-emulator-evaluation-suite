"""put-secret-value-exceeds-size-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-secret-value-exceeds-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSecretValue with a payload exceeding the 65536-character max secret size is rejected, not truncated."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secmgr-oversize-")
    created = sm.create_secret(
        Name=name,
        SecretString="original-in-range-value",
        Tags=[{"Key": "env", "Value": "test"}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    original_version = created["VersionId"]

    # 70000 characters exceeds the documented 65536-character maximum secret value
    # size. botocore's client-side ParamValidator only enforces `min` length (see
    # botocore.validate.range_check), never `max`, so this request is genuinely put
    # on the wire and only the *server* can refuse it -- a ParamValidationError here
    # would mean the request never left the SDK and must not be read as a rejection.
    oversized = "x" * 70000
    rejected = False
    try:
        sm.put_secret_value(SecretId=secret_arn, SecretString=oversized)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException for a 70000-character SecretString, got {code}"
        )
        message = exc.response["Error"].get("Message")
        assert message == (
            "1 validation error detected: Value at 'secretString' failed to satisfy constraint: "
            "Member must have length less than or equal to 65536"
        ), f"unexpected refusal message: {message!r}"
        rejected = True
    assert rejected, "an oversized PutSecretValue payload was not rejected"

    # Effect absent: no new version was created and no truncated value was stored.
    after = sm.describe_secret(SecretId=secret_arn)
    stage_map = after["VersionIdsToStages"]
    assert len(stage_map) == 1, f"the refused write must not mint a version; VersionIdsToStages was {stage_map}"
    assert "AWSCURRENT" in stage_map.get(original_version, []), (
        f"the original version {original_version} must still hold AWSCURRENT, got {stage_map}"
    )
    unchanged = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert unchanged == "original-in-range-value", (
        f"the stored value must be unchanged after the refused oversized write, got {unchanged!r}"
    )

    # Positive control: an in-range payload on the same secret is accepted normally.
    sm.put_secret_value(SecretId=secret_arn, SecretString="in-range-replacement-value")
    replaced = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert replaced == "in-range-replacement-value", (
        f"an in-range PutSecretValue on the same secret must succeed, got {replaced!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
