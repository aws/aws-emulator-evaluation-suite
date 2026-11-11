"""application-assignment-configuration-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-assignment-configuration-round-trip"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """PutApplicationAssignmentConfiguration(AssignmentRequired=...) is reflected exactly by
    GetApplicationAssignmentConfiguration in both directions."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_application_provider_arn(ctx)

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    sso.put_application_assignment_configuration(ApplicationArn=app_arn, AssignmentRequired=False)
    got_false = sso.get_application_assignment_configuration(ApplicationArn=app_arn)["AssignmentRequired"]
    assert got_false is False, f"expected AssignmentRequired=False after Put(False), got {got_false!r}"

    sso.put_application_assignment_configuration(ApplicationArn=app_arn, AssignmentRequired=True)
    got_true = sso.get_application_assignment_configuration(ApplicationArn=app_arn)["AssignmentRequired"]
    assert got_true is True, f"expected AssignmentRequired=True after Put(True), got {got_true!r}"


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
