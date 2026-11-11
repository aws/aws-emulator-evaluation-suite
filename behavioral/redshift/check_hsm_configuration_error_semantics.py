"""hsm-configuration-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hsm-configuration-error-semantics"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHsmConfiguration answers HsmConfigurationAlreadyExistsFault for a duplicate identifier,
    leaving the original unchanged, and InvalidTagFault for a duplicate tag key in one request,
    creating nothing (HsmConfigurationNotFoundFault), each with its exact message."""
    redshift = ctx.client("redshift")
    hsm_id = ctx.unique_name("sim2real-hsmcfg-")
    original_description = "sim2real behavioral fidelity test hsm configuration"
    common_kwargs = dict(
        Description=original_description,
        HsmIpAddress="10.0.0.123",
        HsmPartitionName="testpartition",
        HsmPartitionPassword="TestPassword123!",
        HsmServerPublicCertificate="dGVzdC1jZXJ0LWRhdGEtZm9yLXNpbTJyZWFs",
    )

    redshift.create_hsm_configuration(HsmConfigurationIdentifier=hsm_id, **common_kwargs)
    ctx.on_cleanup(lambda: redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hsm_id))

    # Duplicate identifier -> HsmConfigurationAlreadyExistsFault.
    dup_code, dup_message = _error(
        lambda: redshift.create_hsm_configuration(
            HsmConfigurationIdentifier=hsm_id,
            Description="attempted-overwrite-should-not-stick",
            **{k: v for k, v in common_kwargs.items() if k != "Description"},
        )
    )
    assert dup_code == "HsmConfigurationAlreadyExistsFault", (
        f"expected HsmConfigurationAlreadyExistsFault on duplicate identifier, got {dup_code}"
    )
    expected = (
        "Cannot create the HSM configuration because a configuration with the identifier "
        f"{hsm_id} already exists."
    )
    assert dup_message == expected, f"expected message {expected!r}, got {dup_message!r}"

    # Effect absent (independent read): the rejected duplicate did not mutate the original.
    original = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=hsm_id)[
        "HsmConfigurations"
    ][0]
    assert original["Description"] == original_description, (
        "rejected duplicate create mutated the original configuration"
    )

    # Malformed tag set (duplicate key within the same request) -> InvalidTagFault.
    other_id = ctx.unique_name("sim2real-hsmcfg-badtag-")
    tag_code, tag_message = _error(
        lambda: redshift.create_hsm_configuration(
            HsmConfigurationIdentifier=other_id,
            Tags=[{"Key": "env", "Value": "a"}, {"Key": "env", "Value": "b"}],
            **common_kwargs,
        )
    )
    assert tag_code == "InvalidTagFault", f"expected InvalidTagFault on duplicate tag key, got {tag_code}"
    expected = (
        "Tag key: 'env' has been used more than once. You must use a unique set of keys per api call."
    )
    assert tag_message == expected, f"expected message {expected!r}, got {tag_message!r}"

    # Effect absent (independent read, and the terminal assertion): the rejected
    # tag-invalid create never persisted a configuration under other_id.
    not_created_code, not_created_message = _error(
        lambda: redshift.describe_hsm_configurations(HsmConfigurationIdentifier=other_id)
    )
    assert not_created_code == "HsmConfigurationNotFoundFault", (
        f"rejected create must not have persisted a configuration, got {not_created_code}"
    )
    expected = f"HSM configuration '{other_id}' not found."
    assert not_created_message == expected, f"expected message {expected!r}, got {not_created_message!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError rejection but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
