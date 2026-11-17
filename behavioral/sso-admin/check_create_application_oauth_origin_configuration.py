"""create-application-oauth-origin-configuration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-oauth-origin-configuration"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]

_IDENTITY_CENTER_FOR_OIDC = (
    "ValidationException",
    "SignInOrigin cannot be IDENTITY_CENTER for an OIDC application",
)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:identity-center-instance",
)
def run(ctx) -> None:
    """CreateApplication for an OAuth2.0 provider with Visibility=DISABLED and
    Origin=APPLICATION round-trips through DescribeApplication; the same provider refuses
    Origin=IDENTITY_CENTER, and ListApplications never shows the refused attempt."""
    sso = ctx.client("sso-admin")
    instance_arn = _identity_center_instance_arn(ctx)
    provider_arn = _oauth_provider_arn(sso)

    live_name = ctx.unique_name("sim2real-behav-ssoapp-")
    app_url = "https://app.example.com/login"
    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=live_name,
        Status="DISABLED",
        PortalOptions={
            "Visibility": "DISABLED",
            "SignInOptions": {"Origin": "APPLICATION", "ApplicationUrl": app_url},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    described = sso.describe_application(ApplicationArn=app_arn)
    assert described["Status"] == "DISABLED", (
        f"expected the created application's Status to stay 'DISABLED', got {described['Status']!r}"
    )
    portal = described["PortalOptions"]
    assert portal["Visibility"] == "DISABLED", (
        f"expected PortalOptions.Visibility='DISABLED' to persist, got {portal['Visibility']!r}"
    )
    sign_in = portal["SignInOptions"]
    assert sign_in == {"Origin": "APPLICATION", "ApplicationUrl": app_url}, (
        f"expected SignInOptions {{'Origin': 'APPLICATION', 'ApplicationUrl': {app_url!r}}}, "
        f"got {sign_in!r}"
    )

    # The same provider, same instance, refuses the sign-in origin that only a SAML-based
    # application can use: the application above is this check's positive neighbour, proving
    # the refusal below is specific to the IDENTITY_CENTER origin and not to the setup.
    rejected_name = ctx.unique_name("sim2real-behav-ssoapp-rejected-")
    code, message = _refusal(
        lambda: sso.create_application(
            InstanceArn=instance_arn,
            ApplicationProviderArn=provider_arn,
            Name=rejected_name,
            Status="DISABLED",
            PortalOptions={
                "Visibility": "DISABLED",
                "SignInOptions": {"Origin": "IDENTITY_CENTER"},
            },
        )
    )
    assert (code, message) == _IDENTITY_CENTER_FOR_OIDC, (code, message)

    names = {
        a["Name"]
        for page in sso.get_paginator("list_applications").paginate(InstanceArn=instance_arn)
        for a in page.get("Applications", [])
    }
    assert rejected_name not in names, (
        f"the refused CreateApplication(Origin=IDENTITY_CENTER) left behind {rejected_name!r}"
    )
    assert live_name in names, (
        f"expected the earlier, accepted application {live_name!r} to still be listed, got {sorted(names)!r}"
    )


def _identity_center_instance_arn(ctx) -> str:
    """The account's one IAM Identity Center instance, ACTIVE; created and torn down here if none
    pre-exists, so this check owns exactly the account state it changes."""
    sso = ctx.client("sso-admin")
    existing = sso.list_instances().get("Instances", [])
    if existing:
        return existing[0]["InstanceArn"]

    instance_arn = sso.create_instance(Name=ctx.unique_name("sim2real-behav-ssoins-"))["InstanceArn"]
    ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=instance_arn))

    deadline = time.monotonic() + 120
    status = None
    while time.monotonic() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status not in ("CREATE_IN_PROGRESS", "ACTIVE"):
            raise AssertionError(f"the new Identity Center instance reached status {status!r}, not ACTIVE")
        time.sleep(3)
    raise AssertionError(f"the new Identity Center instance never reached ACTIVE (last status: {status!r})")


def _oauth_provider_arn(sso) -> str:
    """The ARN of an OAuth2.0 customer-managed application provider, which is the only kind
    CreateApplication accepts."""
    providers = sso.list_application_providers().get("ApplicationProviders", [])
    for provider in providers:
        if provider["FederationProtocol"] == "OAUTH" and provider["ApplicationProviderArn"].endswith("/custom"):
            return provider["ApplicationProviderArn"]
    raise AssertionError(f"no OAuth2.0 customer-managed application provider found among {providers!r}")


def _refusal(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success is itself the failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
