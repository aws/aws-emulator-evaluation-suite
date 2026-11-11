"""create-tenant-resource-association-unsupported-resource-type-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tenant-resource-association-unsupported-resource-type-blocked"
GROUP = "overly-permissive"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTenantResourceAssociation rejects a non-SES ARN (SNS topic) with BadRequestException,
    leaving the tenant's resources unchanged; a configuration-set ARN associates and is listed."""
    ses = ctx.client("sesv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    tags = [{"Key": "env", "Value": "test"}]

    tenant_name = ctx.unique_name("sim2real-tenant-")
    ses.create_tenant(TenantName=tenant_name, Tags=tags)
    ctx.on_cleanup(lambda: ses.delete_tenant(TenantName=tenant_name))

    unsupported_arn = f"arn:aws:sns:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-topic-')}"
    err = _error(
        lambda: ses.create_tenant_resource_association(
            TenantName=tenant_name, ResourceArn=unsupported_arn
        )
    )
    expected = ("BadRequestException", "Provided ARN is not in SES resource ARN format")
    assert err == expected, f"expected {expected!r}, got {err!r}"

    resources_after_reject = ses.list_tenant_resources(TenantName=tenant_name)["TenantResources"]
    assert all(r["ResourceArn"] != unsupported_arn for r in resources_after_reject), (
        f"rejected SNS topic ARN {unsupported_arn!r} still appears in "
        f"{resources_after_reject!r}"
    )

    # positive control: a supported resource type (configuration set) associates fine.
    config_set_name = ctx.unique_name("sim2real-cs-")
    ses.create_configuration_set(ConfigurationSetName=config_set_name, Tags=tags)
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=config_set_name))
    config_set_arn = f"arn:aws:ses:{ctx.region}:{account_id}:configuration-set/{config_set_name}"

    ses.create_tenant_resource_association(TenantName=tenant_name, ResourceArn=config_set_arn)
    ctx.on_cleanup(
        lambda: ses.delete_tenant_resource_association(
            TenantName=tenant_name, ResourceArn=config_set_arn
        )
    )

    resources_after_accept = ses.list_tenant_resources(TenantName=tenant_name)["TenantResources"]
    assert any(r["ResourceArn"] == config_set_arn for r in resources_after_accept), (
        f"supported configuration-set ARN {config_set_arn!r} missing from "
        f"{resources_after_accept!r}"
    )


def _error(fn):
    """Call fn() and return its botocore error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    raise AssertionError(
        f"real AWS rejects this ResourceArn, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
