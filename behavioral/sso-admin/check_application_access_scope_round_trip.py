"""application-access-scope-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-access-scope-round-trip"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """PutApplicationAccessScope's AuthorizedTargets round-trip through GetApplicationAccessScope
    and ListApplicationAccessScopes, and DeleteApplicationAccessScope removes the scope entirely."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    scope = "s3:access_grants:read_write"
    sso.put_application_access_scope(ApplicationArn=app_arn, Scope=scope, AuthorizedTargets=[app_arn])

    fetched = sso.get_application_access_scope(ApplicationArn=app_arn, Scope=scope)
    assert fetched["Scope"] == scope, f"expected Scope={scope!r}, got {fetched['Scope']!r}"
    assert fetched["AuthorizedTargets"] == [app_arn], (
        f"expected AuthorizedTargets=[{app_arn!r}], got {fetched['AuthorizedTargets']!r}"
    )

    listed = sso.list_application_access_scopes(ApplicationArn=app_arn)["Scopes"]
    assert any(s["Scope"] == scope and s["AuthorizedTargets"] == [app_arn] for s in listed), (
        f"expected {scope!r} with AuthorizedTargets=[{app_arn!r}] in ListApplicationAccessScopes, got {listed!r}"
    )

    sso.delete_application_access_scope(ApplicationArn=app_arn, Scope=scope)

    code, message = _error(lambda: sso.get_application_access_scope(ApplicationArn=app_arn, Scope=scope))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert message == f"No access scope {scope} found for application arn: {app_arn}", message

    # The deleted scope is gone, not just unreadable: a second delete on the same dead id also
    # fails not-found rather than succeeding as a silent no-op.
    redelete_code, redelete_msg = _error(lambda: sso.delete_application_access_scope(ApplicationArn=app_arn, Scope=scope))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on a second delete of an already-deleted scope, got {redelete_code!r}"
    )
    assert redelete_msg == f"No access scope {scope} found for application arn: {app_arn}", redelete_msg


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
    # "custom" is the generic customer-managed OAuth 2.0 provider -- unlike AWS-managed OAUTH
    # providers (glue, athena, codewhisperer, ...), it accepts CreateApplication directly and
    # is supported for account instances of IAM Identity Center.
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
