"""start-session-missing-permission-access-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-session-missing-permission-access-denied"
GROUP = "overly-permissive"
SERVICES = ["appconfigdata"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM principal with no appconfig/appconfigdata permissions is denied
    StartConfigurationSession, while the fully-permissioned test principal still
    succeeds against the identical application/environment/profile."""
    app_id, env_id, profile_id = _setup_deployed_profile(ctx, content=b'{"ok":true}', content_type="application/json")

    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-acd-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: iam.delete_role(RoleName=role_name)))

    # No permission policy is attached: the role has no allow for appconfig/appconfigdata,
    # so any such call is denied by IAM's implicit-deny default.
    session_name = ctx.unique_name("sim2real-acd-sess-")
    creds = _wait_for_assumable_role(ctx, role_arn, session_name)
    restricted_appconfigdata = ctx.client(
        "appconfigdata",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    code, message = _wait_past_credential_propagation_lag(
        lambda: restricted_appconfigdata.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=profile_id,
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException for the unpermissioned role, got {code!r}"
    action = "appconfig:StartConfigurationSession"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} "
        f"is not authorized to perform: {action} on resource: "
        f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"
        f"/environment/{env_id}/configuration/{profile_id} "
        f"because no identity-based policy allows the {action} action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the original, fully-permissioned principal still succeeds, and the
    # token it receives is independently proven usable against GetLatestConfiguration —
    # the destination read, not the mutating call's own response.
    appconfigdata = ctx.client("appconfigdata")
    control = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_id,
    )
    token = control["InitialConfigurationToken"]
    assert token, f"expected a non-empty InitialConfigurationToken from the permissioned principal, got {token!r}"
    fetched = appconfigdata.get_latest_configuration(ConfigurationToken=token)
    fetched_body = fetched["Configuration"].read()
    assert fetched_body == b'{"ok":true}', (
        f"expected the deployed content b'{{\"ok\":true}}' via the independent read, got {fetched_body!r}"
    )


def _client_error(fn):
    """Return (code, message) for a call that must be refused.

    Raises AssertionError when the call succeeds: an emulator that accepts what AWS refuses
    must fail loudly, not read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {result!r}")


def _wait_past_credential_propagation_lag(fn, timeout_s=20.0):
    """IAM's implicit deny is immediate, but a JUST-assumed role's credentials can take a few
    seconds to propagate to services outside STS itself; a call issued too soon fails signature
    validation (UnrecognizedClientException / InvalidClientTokenId) rather than authorization.
    Retry past that specific race only; any other refusal is terminal and returned as
    (code, message), and an unexpected success raises."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while True:
        code, message = _client_error(fn)
        if code not in ("UnrecognizedClientException", "InvalidClientTokenId"):
            return code, message
        last_code = code
        if time.monotonic() >= deadline:
            raise AssertionError(f"credentials never propagated within {timeout_s}s: last saw {last_code!r}")
        time.sleep(2)


def _ignore_not_found(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
        if code != "ResourceNotFoundException":
            raise


def _wait_for_assumable_role(ctx, role_arn, session_name, timeout_s=90.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_err}")


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-acd-app-"), Tags={"sim2real-check": CHECK}
    )["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _create_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-acd-env-"), Tags={"sim2real-check": CHECK}
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))
    )
    return env_id


def _create_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-acd-profile-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags={"sim2real-check": CHECK},
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
        )
    )
    return profile_id


def _create_hosted_version(ctx, app_id, profile_id, content, content_type="application/json"):
    appconfig = ctx.client("appconfig")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType=content_type,
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: appconfig.delete_hosted_configuration_version(
                ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
            )
        )
    )
    return version_number


def _deploy_version(ctx, app_id, env_id, profile_id, version_number, timeout_s=150.0):
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-acd-strat-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags={"sim2real-check": CHECK},
    )["Id"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))
    )
    resp = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = resp["DeploymentNumber"]
    state = resp.get("State")
    deadline = time.monotonic() + timeout_s
    while state != "COMPLETE" and time.monotonic() < deadline:
        if state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment entered terminal failure state {state}")
        time.sleep(3)
        state = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )["State"]
    if state != "COMPLETE":
        raise AssertionError(f"deployment did not reach COMPLETE within {timeout_s}s, last state={state}")
    return deployment_number


def _setup_deployed_profile(ctx, content=b'{"flag":true}', content_type="application/json"):
    app_id = _create_application(ctx)
    env_id = _create_environment(ctx, app_id)
    profile_id = _create_profile(ctx, app_id)
    version_number = _create_hosted_version(ctx, app_id, profile_id, content, content_type)
    _deploy_version(ctx, app_id, env_id, profile_id, version_number)
    return app_id, env_id, profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
