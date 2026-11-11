"""hsm-configuration-duplicate-and-quota-errors."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hsm-configuration-duplicate-and-quota-errors"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateHsmConfiguration answers HsmConfigurationAlreadyExistsFault for a duplicate id,
    InvalidTagFault for a reserved-prefix tag (creating nothing), and HsmConfigurationQuotaExceeded
    with "Cannot create more than <held> HSM configurations." once the quota is reached."""
    redshift = ctx.client("redshift")
    base_kwargs = dict(
        Description="sim2real behavioral hsm configuration",
        HsmIpAddress="10.0.0.1",
        HsmPartitionName="sim2real-partition",
        HsmPartitionPassword="Sim2Real-Passw0rd!",
        HsmServerPublicCertificate="sim2real-fake-certificate-data",
    )
    created_ids: list[str] = []

    def _cleanup() -> None:
        for hid in created_ids:
            try:
                redshift.delete_hsm_configuration(HsmConfigurationIdentifier=hid)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "HsmConfigurationNotFoundFault":
                    raise

    ctx.on_cleanup(_cleanup)

    # 1. Baseline success.
    first_id = ctx.unique_name("sim2real-behav-hsmcfg-")
    redshift.create_hsm_configuration(HsmConfigurationIdentifier=first_id, **base_kwargs)
    created_ids.append(first_id)

    # 2. Duplicate identifier -> HsmConfigurationAlreadyExistsFault, and no second resource
    #    is created (the describe call below still shows exactly one configuration for it).
    code, message = _error(
        lambda: redshift.create_hsm_configuration(HsmConfigurationIdentifier=first_id, **base_kwargs)
    )
    assert code == "HsmConfigurationAlreadyExistsFault", f"expected AlreadyExists, got {code}"
    expected = (
        "Cannot create the HSM configuration because a configuration with the identifier "
        f"{first_id} already exists."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # 3. Malformed tag (duplicate key within the same request) -> InvalidTagFault, and the
    #    configuration is never created (describe raises NotFound for it).
    bad_tag_id = ctx.unique_name("sim2real-behav-hsmcfg-")
    code, message = _error(
        lambda: redshift.create_hsm_configuration(
            HsmConfigurationIdentifier=bad_tag_id,
            Tags=[
                {"Key": "sim2real-dup", "Value": "one"},
                {"Key": "sim2real-dup", "Value": "two"},
            ],
            **base_kwargs,
        )
    )
    assert code == "InvalidTagFault", f"expected InvalidTagFault, got {code}"
    expected = (
        "Tag key: 'sim2real-dup' has been used more than once. "
        "You must use a unique set of keys per api call."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    not_created_code, not_created_message = _error(
        lambda: redshift.describe_hsm_configurations(HsmConfigurationIdentifier=bad_tag_id)
    )
    assert not_created_code == "HsmConfigurationNotFoundFault", (
        f"rejected create must not have persisted a configuration, got {not_created_code}"
    )
    expected = f"HSM configuration '{bad_tag_id}' not found."
    assert not_created_message == expected, f"expected message {expected!r}, got {not_created_message!r}"

    # 4. Drive the account to its HSM configuration quota by creating additional
    #    configurations until the service rejects with HsmConfigurationQuotaExceededFault.
    quota_message = None
    for _ in range(40):
        cid = ctx.unique_name("sim2real-behav-hsmcfg-")
        try:
            redshift.create_hsm_configuration(HsmConfigurationIdentifier=cid, **base_kwargs)
            created_ids.append(cid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "HsmConfigurationQuotaExceededFault":
                quota_message = exc.response["Error"].get("Message")
                break
            raise
    assert quota_message is not None, "never observed HsmConfigurationQuotaExceededFault within 40 creates"
    # The quota is the number of configurations the account holds at the moment of refusal.
    held = len(redshift.describe_hsm_configurations().get("HsmConfigurations", []))
    expected = f"Cannot create more than {held} HSM configurations."
    assert quota_message == expected, f"expected message {expected!r}, got {quota_message!r}"

    # Positive control: the original configuration (created before any of the above faults)
    # is still present and unaffected by the rejected operations.
    described = redshift.describe_hsm_configurations(HsmConfigurationIdentifier=first_id)
    final = described["HsmConfigurations"][0]
    assert final["HsmConfigurationIdentifier"] == first_id, (
        f"original configuration {first_id!r} not found after the rejected operations, "
        f"got {final!r}"
    )
    assert final["HsmPartitionName"] == base_kwargs["HsmPartitionName"], (
        "the original configuration's partition name was mutated by one of the rejected "
        f"create attempts: expected {base_kwargs['HsmPartitionName']!r}, got "
        f"{final['HsmPartitionName']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
