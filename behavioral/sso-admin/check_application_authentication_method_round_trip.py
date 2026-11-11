"""application-authentication-method-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "application-authentication-method-round-trip"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """PutApplicationAuthenticationMethod(Iam) round-trips through
    GetApplicationAuthenticationMethod and ListApplicationAuthenticationMethods, and
    DeleteApplicationAuthenticationMethod removes it entirely (subsequent Get 404s)."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    method_type = "IAM"
    actor_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sso-oauth:CreateTokenWithIAM",
                "Resource": "*",
            }
        ],
    }
    sso.put_application_authentication_method(
        ApplicationArn=app_arn,
        AuthenticationMethodType=method_type,
        AuthenticationMethod={"Iam": {"ActorPolicy": actor_policy}},
    )

    fetched = sso.get_application_authentication_method(
        ApplicationArn=app_arn, AuthenticationMethodType=method_type
    )["AuthenticationMethod"]
    round_tripped = json.loads(json.dumps(fetched["Iam"]["ActorPolicy"]))
    assert round_tripped == actor_policy, f"expected ActorPolicy to round-trip as {actor_policy!r}, got {round_tripped!r}"

    listed = sso.list_application_authentication_methods(ApplicationArn=app_arn)["AuthenticationMethods"]
    listed_types = [m["AuthenticationMethodType"] for m in listed]
    assert method_type in listed_types, f"expected {method_type!r} in ListApplicationAuthenticationMethods, got {listed_types!r}"

    sso.delete_application_authentication_method(ApplicationArn=app_arn, AuthenticationMethodType=method_type)

    code, message = _error(
        lambda: sso.get_application_authentication_method(
            ApplicationArn=app_arn, AuthenticationMethodType=method_type
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on Get after delete, got {code!r}"
    assert message == f"No authentication method {method_type} found for application arn: {app_arn}", message

    redelete_code, redelete_msg = _error(
        lambda: sso.delete_application_authentication_method(ApplicationArn=app_arn, AuthenticationMethodType=method_type)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second Delete of the same authentication method to also fail with "
        f"ResourceNotFoundException (it must really be gone, not merely hidden from Get), got {redelete_code!r}"
    )
    assert redelete_msg == f"No authentication method {method_type} found for application arn: {app_arn}", redelete_msg


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

