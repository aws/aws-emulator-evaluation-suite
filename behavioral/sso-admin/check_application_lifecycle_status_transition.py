"""application-lifecycle-status-transition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-lifecycle-status-transition"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateApplication defaults to ENABLED, DescribeApplication reflects it, and
    UpdateApplication(Status=DISABLED) transitions and persists the new status."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_application_provider_arn(ctx)

    name = ctx.unique_name("sim2real-behav-app-")
    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    described = sso.describe_application(ApplicationArn=app_arn)
    assert described["Name"] == name, f"expected Name {name!r}, got {described['Name']!r}"
    assert described["Status"] == "ENABLED", (
        f"expected CreateApplication to default Status to ENABLED, got {described['Status']!r}"
    )
    assert described["ApplicationProviderArn"] == provider_arn, (
        f"expected ApplicationProviderArn {provider_arn!r}, got {described['ApplicationProviderArn']!r}"
    )

    sso.update_application(ApplicationArn=app_arn, Status="DISABLED")

    after_disable = sso.describe_application(ApplicationArn=app_arn)
    assert after_disable["Status"] == "DISABLED", (
        f"expected Status DISABLED after UpdateApplication, got {after_disable['Status']!r}"
    )

    sso.update_application(ApplicationArn=app_arn, Status="ENABLED")

    after_enable = sso.describe_application(ApplicationArn=app_arn)
    assert after_enable["Status"] == "ENABLED", (
        f"expected Status ENABLED after re-enabling, got {after_enable['Status']!r}"
    )


def _get_instance_arn(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _pick_application_provider_arn(ctx):

    sso = ctx.client("sso-admin")
    providers = {p["ApplicationProviderArn"] for p in sso.list_application_providers().get("ApplicationProviders", [])}
    custom_arn = "arn:aws:sso::aws:applicationProvider/custom"
    if custom_arn not in providers:
        raise AssertionError("the generic customer-managed OAuth2 application provider is not available in this partition")
    return custom_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
