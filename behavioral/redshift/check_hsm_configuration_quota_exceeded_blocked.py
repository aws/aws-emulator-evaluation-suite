"""hsm-configuration-quota-exceeded-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hsm-configuration-quota-exceeded-blocked"
GROUP = "overly-permissive"
SERVICES = ["redshift"]

# Redshift does not publish an "HSM configuration" quota through Service Quotas
# (list_service_quotas / list_aws_default_service_quotas for ServiceCode="redshift"
# lists 29 other quotas but never one for HSM configurations, confirmed against real
# AWS), so the limit cannot be discovered and is only raisable via an AWS Support
# case. This bounds the probing loop; it is not an asserted expected value.
MAX_PROBE_ATTEMPTS = 60


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Exceeding the account's HsmConfiguration quota is rejected with
    HsmConfigurationQuotaExceededFault instead of the account being allowed to hold
    an unbounded number of HSM configurations."""
    redshift = ctx.client("redshift")
    baseline = len(redshift.describe_hsm_configurations().get("HsmConfigurations", []))
    created: list[str] = []

    def _cleanup_created():
        for name in created:
            try:
                redshift.delete_hsm_configuration(HsmConfigurationIdentifier=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "HsmConfigurationNotFoundFault":
                    raise

    ctx.on_cleanup(_cleanup_created)

    hit_quota_fault = False
    rejected_name: str | None = None
    quota_message: str | None = None
    for i in range(MAX_PROBE_ATTEMPTS):
        name = ctx.unique_name(f"sim2real-hsmq-{i}-")
        try:
            redshift.create_hsm_configuration(
                HsmConfigurationIdentifier=name,
                Description="sim2real quota probe",
                HsmIpAddress="10.0.1.10",
                HsmPartitionName="partition-quota",
                HsmPartitionPassword="QuotaPassw0rd!23",
                HsmServerPublicCertificate="QUOTA-CERT-BODY",
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            created.append(name)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "HsmConfigurationQuotaExceededFault":
                hit_quota_fault = True
                rejected_name = name
                quota_message = err.response["Error"].get("Message")
                break
            raise

    assert hit_quota_fault, (
        f"expected HsmConfigurationQuotaExceededFault within {MAX_PROBE_ATTEMPTS} "
        f"creates (baseline {baseline} existing configs); the account's HSM "
        "configuration quota may have been raised well beyond this probe's bound"
    )

    all_ids = {
        c["HsmConfigurationIdentifier"]
        for c in redshift.describe_hsm_configurations().get("HsmConfigurations", [])
    }
    # The quota is the number of configurations the account holds at the moment of refusal.
    expected_quota = f"Cannot create more than {len(all_ids)} HSM configurations."
    assert quota_message == expected_quota, f"expected message {expected_quota!r}, got {quota_message!r}"
    # The accepted creates all persisted...
    assert all(name in all_ids for name in created)
    # ...and the rejected over-quota config must not exist.
    assert rejected_name not in all_ids, (
        f"{rejected_name} was rejected with HsmConfigurationQuotaExceededFault but is "
        "visible in DescribeHsmConfigurations"
    )

    # Positive control: after freeing up quota by deleting one, creating a fresh
    # config succeeds again.
    freed_name = created.pop()
    redshift.delete_hsm_configuration(HsmConfigurationIdentifier=freed_name)
    try:
        redshift.describe_hsm_configurations(HsmConfigurationIdentifier=freed_name)
    except ClientError as err:
        freed_code = err.response["Error"]["Code"]
        freed_message = err.response["Error"].get("Message")
    else:
        raise AssertionError(f"DescribeHsmConfigurations still returned deleted {freed_name}")
    assert freed_code == "HsmConfigurationNotFoundFault", (
        f"expected HsmConfigurationNotFoundFault for deleted {freed_name}, got {freed_code}"
    )
    expected_freed = f"HSM configuration '{freed_name}' not found."
    assert freed_message == expected_freed, f"expected message {expected_freed!r}, got {freed_message!r}"
    control_name = ctx.unique_name("sim2real-hsmq-ctrl-")
    redshift.create_hsm_configuration(
        HsmConfigurationIdentifier=control_name,
        Description="sim2real quota control",
        HsmIpAddress="10.0.1.20",
        HsmPartitionName="partition-quota-ctrl",
        HsmPartitionPassword="QuotaCtrlPassw0rd!23",
        HsmServerPublicCertificate="QUOTA-CTRL-CERT-BODY",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    created.append(control_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
