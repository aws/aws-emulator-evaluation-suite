"""appconfigdata-poll-interval-ceiling-and-gated-resume-after-wait."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "appconfigdata-poll-interval-ceiling-and-gated-resume-after-wait"
GROUP = "configuration-data-plane"
SERVICES = ["appconfigdata"]

_INTERVAL_TOO_HIGH = (
    "BadRequestException",
    "1 validation error detected: Value '86401' at 'requiredMinimumPollIntervalInSeconds' "
    "failed to satisfy constraint: Member must have value less than or equal to 86400",
)

_TOO_EARLY = ("BadRequestException", "Request too early")

_MAX_INTERVAL_S = 86400
_PRACTICAL_INTERVAL_S = 15


def expect_error(fn, code, message) -> None:
    """Call fn(); assert it raises exactly (code, message). An unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got_code, got_message = err.get("Code"), err.get("Message")
        assert got_code == code, f"expected error code {code!r}, got {got_code!r} ({got_message!r})"
        assert got_message == message, f"expected message {message!r}, got {got_message!r}"
        return
    raise AssertionError(f"expected {code} ({message!r}), but the call succeeded: {result!r}")


def _delete_or_absent(delete) -> None:
    """Run delete(); the resource's own not-found code means it is already gone."""
    try:
        delete()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _new_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: _delete_or_absent(lambda: appconfig.delete_application(ApplicationId=app_id)))
    return app_id


def _new_environment(ctx, app_id):
    appconfig = ctx.client("appconfig")
    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-")
    )["Id"]
    ctx.on_cleanup(lambda: _delete_or_absent(
        lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    ))
    return env_id


def _new_configuration_profile(ctx, app_id):
    appconfig = ctx.client("appconfig")
    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-profile-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
    )["Id"]
    ctx.on_cleanup(lambda: _delete_or_absent(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    ))
    return profile_id


def _new_deployment_strategy(ctx):
    appconfig = ctx.client("appconfig")
    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-strategy-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: _delete_or_absent(
        lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id)
    ))
    return strategy_id


def _new_hosted_version(ctx, app_id, profile_id, content: bytes, content_type: str):
    appconfig = ctx.client("appconfig")
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType=content_type,
    )["VersionNumber"]
    ctx.on_cleanup(lambda: _delete_or_absent(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    ))
    return version_number


def _run_deployment_to_completion(ctx, app_id, env_id, profile_id, strategy_id, version_number,
                                   timeout_s: float = 120.0) -> None:
    appconfig = ctx.client("appconfig")
    deployment_number = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )["State"]
        if state == "COMPLETE":
            return
        if state in ("ROLLED_BACK", "REVERTED"):
            raise AssertionError(f"deployment reached {state!r} instead of COMPLETE")
        time.sleep(2.0)
    raise AssertionError(f"deployment did not reach COMPLETE within {timeout_s}s, last state={state!r}")


def _provision_deployed_configuration(ctx, content: bytes, content_type: str):
    """Create an application/environment/profile and deploy content to it; return their ids."""
    app_id = _new_application(ctx)
    env_id = _new_environment(ctx, app_id)
    profile_id = _new_configuration_profile(ctx, app_id)
    strategy_id = _new_deployment_strategy(ctx)
    version_number = _new_hosted_version(ctx, app_id, profile_id, content, content_type)
    _run_deployment_to_completion(ctx, app_id, env_id, profile_id, strategy_id, version_number)
    return app_id, env_id, profile_id


def _poll_until_accepted(fn, *, budget_s: float = 45.0, retry_s: float = 2.0):
    """Retry fn() while it raises exactly the documented too-early refusal; return its result."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (err.get("Code"), err.get("Message")) != _TOO_EARLY:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the gated poll interval never elapsed within {budget_s}s")
            time.sleep(retry_s)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartConfigurationSession refuses a RequiredMinimumPollIntervalInSeconds of 86401, one past
    the documented maximum; 86400 opens a session serving the deployed configuration at that
    interval, and a poll gated at 15 seconds reports it unchanged, empty, with a fresh token.
    """
    content = b'{"ceiling": "checked"}'
    app_id, env_id, profile_id = _provision_deployed_configuration(
        ctx, content, content_type="application/json"
    )

    # botocore would reject 86401 locally from the model's range:[15,86400] trait, so disable
    # parameter validation to let the request reach the service.
    unvalidated = ctx.client("appconfigdata", config=Config(parameter_validation=False))
    expect_error(
        lambda: unvalidated.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=profile_id,
            RequiredMinimumPollIntervalInSeconds=_MAX_INTERVAL_S + 1,
        ),
        *_INTERVAL_TOO_HIGH,
    )

    appconfigdata = ctx.client("appconfigdata")
    ceiling_session = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_id,
        RequiredMinimumPollIntervalInSeconds=_MAX_INTERVAL_S,
    )
    ceiling_first = appconfigdata.get_latest_configuration(
        ConfigurationToken=ceiling_session["InitialConfigurationToken"]
    )
    ceiling_body = ceiling_first["Configuration"].read()
    assert ceiling_body == content, (
        f"a session opened at the documented maximum poll interval must still serve the "
        f"deployed configuration, got {ceiling_body!r}"
    )
    assert ceiling_first["NextPollIntervalInSeconds"] == _MAX_INTERVAL_S, (
        f"NextPollIntervalInSeconds was {ceiling_first['NextPollIntervalInSeconds']!r}, "
        f"expected the requested {_MAX_INTERVAL_S}"
    )

    gated_session = appconfigdata.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=profile_id,
        RequiredMinimumPollIntervalInSeconds=_PRACTICAL_INTERVAL_S,
    )
    gated_first = appconfigdata.get_latest_configuration(
        ConfigurationToken=gated_session["InitialConfigurationToken"]
    )
    gated_first_body = gated_first["Configuration"].read()
    assert gated_first_body == content, (
        f"the first poll of a session gated at the minimum poll interval must still serve the "
        f"deployed configuration, got {gated_first_body!r}"
    )
    pending_token = gated_first["NextPollConfigurationToken"]

    gated_second = _poll_until_accepted(
        lambda: appconfigdata.get_latest_configuration(ConfigurationToken=pending_token)
    )
    gated_second_body = gated_second["Configuration"].read()
    assert gated_second_body == b"", (
        f"once the gated interval elapses, a poll with no intervening deployment must report "
        f"unchanged with an empty payload, got {len(gated_second_body)} byte(s) "
        f"({gated_second_body[:64]!r})"
    )
    assert gated_second["NextPollConfigurationToken"] != pending_token, (
        "the accepted poll must mint a fresh NextPollConfigurationToken, even though the "
        "configuration itself is unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
