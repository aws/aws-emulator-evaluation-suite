"""application-grant-refresh-token-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-grant-refresh-token-round-trip"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """PutApplicationGrant(refresh_token) makes the grant readable via GetApplicationGrant and
    ListApplicationGrants; before the put and after DeleteApplicationGrant, GetApplicationGrant (and a second delete)
    fail with ResourceNotFoundException "No grant <type> found for application arn: <arn>" and the list omits it."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    grant_type = "refresh_token"

    # Not configured yet: Get 404s.
    code_before, msg_before = _error(lambda: sso.get_application_grant(ApplicationArn=app_arn, GrantType=grant_type))
    assert code_before == "ResourceNotFoundException", (
        f"an unconfigured grant should read back ResourceNotFoundException, got {code_before!r}"
    )
    assert msg_before == f"No grant {grant_type} found for application arn: {app_arn}", msg_before

    sso.put_application_grant(ApplicationArn=app_arn, GrantType=grant_type, Grant={"RefreshToken": {}})

    fetched = sso.get_application_grant(ApplicationArn=app_arn, GrantType=grant_type)["Grant"]
    assert "RefreshToken" in fetched, f"GetApplicationGrant did not echo the configured grant: {fetched!r}"

    listed_types = {g["GrantType"] for g in sso.list_application_grants(ApplicationArn=app_arn)["Grants"]}
    assert grant_type in listed_types, (
        f"ListApplicationGrants did not include {grant_type!r} after PutApplicationGrant: {listed_types!r}"
    )

    sso.delete_application_grant(ApplicationArn=app_arn, GrantType=grant_type)

    code_after, msg_after = _error(lambda: sso.get_application_grant(ApplicationArn=app_arn, GrantType=grant_type))
    assert code_after == "ResourceNotFoundException", (
        f"a deleted grant should read back ResourceNotFoundException, got {code_after!r}"
    )
    assert msg_after == f"No grant {grant_type} found for application arn: {app_arn}", msg_after

    listed_after = {g["GrantType"] for g in sso.list_application_grants(ApplicationArn=app_arn)["Grants"]}
    assert grant_type not in listed_after, (
        f"ListApplicationGrants still shows {grant_type!r} after DeleteApplicationGrant: {listed_after!r}"
    )

    code_double_delete, msg_double_delete = _error(lambda: sso.delete_application_grant(ApplicationArn=app_arn, GrantType=grant_type))
    assert code_double_delete == "ResourceNotFoundException", (
        f"deleting an already-deleted grant should read back ResourceNotFoundException, got "
        f"{code_double_delete!r}"
    )
    assert msg_double_delete == f"No grant {grant_type} found for application arn: {app_arn}", msg_double_delete


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


def _pick_oauth_provider_arn(ctx):

    sso = ctx.client("sso-admin")
    providers = {p["ApplicationProviderArn"] for p in sso.list_application_providers().get("ApplicationProviders", [])}
    custom_arn = "arn:aws:sso::aws:applicationProvider/custom"
    if custom_arn not in providers:
        raise AssertionError("the generic customer-managed OAuth2 application provider is not available in this partition")
    return custom_arn


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts a call AWS refuses fails loudly rather than reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


