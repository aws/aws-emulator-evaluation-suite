"""update-ops-metadata-invalid-argument-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-ops-metadata-invalid-argument-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOpsMetadata with a whitespace-only key fails with the exact key-pattern ValidationException before the
    ARN is resolved, while a valid key on the same unknown ARN fails with OpsMetadataNotFoundException, before and
    after."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:ssm:{ctx.region}:{account_id}:opsmetadata/AWS-QuickSetup/"
        f"{ctx.unique_name('sim2real-ssm-opsmeta-nonexistent-')}"
    )

    # positive control: a well-formed update on the same (nonexistent) ARN reaches the
    # existence check and is rejected as not-found -- proving the request/endpoint plumbing is
    # healthy, and giving a second, distinct code to contrast the malformed case against.
    baseline_error = _error(
        lambda: ssm.update_ops_metadata(
            OpsMetadataArn=fake_arn, MetadataToUpdate={"Owner": {"Value": "sim2real"}}
        )
    )
    assert baseline_error.get("Code") == "OpsMetadataNotFoundException", (
        f"expected OpsMetadataNotFoundException for a well-formed update on a nonexistent "
        f"OpsMetadataArn, got {baseline_error!r}"
    )
    assert baseline_error.get("Message") == (
        'OpsMetadata object not found. Verify the Amazon Resource Name (ARN) and try again.'
    ), (
        f"unexpected not-found message: {baseline_error!r}"
    )

    # break exactly one thing: a metadata key that is empty/whitespace-only
    error = _error(
        lambda: ssm.update_ops_metadata(
            OpsMetadataArn=fake_arn, MetadataToUpdate={"   ": {"Value": "bad"}}
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for a whitespace-only metadata key, got {error!r}"
    )
    assert error.get("Message") == (
        "1 validation error detected: Value '{   =MetadataValue(value=bad)}' at 'metadataToUpdate' failed to satisfy constraint: "
        'Map keys must satisfy constraint: [Member must have length less than or equal to 256, Member must have length greater than or equal to 1, Member must satisfy regular expression pattern: ^(?!\\s*$).+]'
    ), (
        f"expected the rejection message to name the metadataToUpdate field, got {error!r}"
    )

    # effect absent: the malformed call never got past shape validation -- an independent read
    # confirms the ARN is exactly as unprovisioned as before it
    still_missing = _error(lambda: ssm.get_ops_metadata(OpsMetadataArn=fake_arn))
    assert still_missing.get("Code") == "OpsMetadataNotFoundException", (
        f"expected the OpsMetadataArn to remain not-found after the rejected update, got "
        f"{still_missing!r}"
    )
    assert still_missing.get("Message") == (
        'OpsMetadata object not found. Verify the Amazon Resource Name (ARN) and try again.'
    ), (
        f"unexpected not-found message: {still_missing!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
