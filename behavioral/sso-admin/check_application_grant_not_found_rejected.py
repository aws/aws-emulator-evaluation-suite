"""application-grant-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-grant-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """GetApplicationGrant / DeleteApplicationGrant for a grant type that was never configured
    on the application are both rejected with ResourceNotFoundException, and putting that grant
    type first makes both calls succeed against the identical application."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
        Tags=[{"Key": "owner", "Value": "fidelity"}],
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    grant_type = "refresh_token"

    code_get, msg_get = _error(lambda: sso.get_application_grant(ApplicationArn=app_arn, GrantType=grant_type))
    assert code_get == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_get!r}"
    assert msg_get == f"No grant {grant_type} found for application arn: {app_arn}", msg_get

    code_delete, msg_delete = _error(
        lambda: sso.delete_application_grant(ApplicationArn=app_arn, GrantType=grant_type)
    )
    assert (
        code_delete == "ResourceNotFoundException"
    ), f"expected ResourceNotFoundException, got {code_delete!r}"
    assert msg_delete == f"No grant {grant_type} found for application arn: {app_arn}", msg_delete

    # Positive control: configuring the grant first makes both calls succeed.
    sso.put_application_grant(ApplicationArn=app_arn, GrantType=grant_type, Grant={"RefreshToken": {}})
    fetched = sso.get_application_grant(ApplicationArn=app_arn, GrantType=grant_type)["Grant"]
    assert "RefreshToken" in fetched, f"expected a RefreshToken grant, got {fetched!r}"
    sso.delete_application_grant(ApplicationArn=app_arn, GrantType=grant_type)

    # The delete is unasserted otherwise: prove the grant is gone via an independent read,
    # the identical not-found contract the check opened with.
    code_get_after_delete, msg_get_after_delete = _error(
        lambda: sso.get_application_grant(ApplicationArn=app_arn, GrantType=grant_type)
    )
    assert (
        code_get_after_delete == "ResourceNotFoundException"
    ), f"expected ResourceNotFoundException after delete, got {code_get_after_delete!r}"
    assert msg_get_after_delete == f"No grant {grant_type} found for application arn: {app_arn}", msg_get_after_delete


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
    accepts a call AWS refuses fails loudly instead of reading as a code mismatch."""
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

