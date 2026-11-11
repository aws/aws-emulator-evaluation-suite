"""corrupted-configuration-token-rejected-with-problem-detail."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "corrupted-configuration-token-rejected-with-problem-detail"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfigdata']

# AppConfig teardown must run bottom-up: DeleteApplication is refused while any environment or
# configuration profile survives, and DeleteConfigurationProfile while any hosted version survives.

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfigdata-corrupted-token"}


def _items(pages):
    """Flatten an AppConfig paginator's pages into one list of items.

    Every page is read because AppConfig refuses a parent delete while any child survives.
    """
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and everything beneath it, bottom-up; raises if it cannot finish."""
    try:
        environments = _items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for env in environments:
        env_id = env["Id"]
        # A per-environment budget, so earlier environments cannot exhaust a later one's wait.
        deadline = time.monotonic() + timeout_s
        for dep in _items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        ):
            if dep.get("State") in _DEPLOYMENT_TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "BadRequestException", "ResourceNotFoundException",
                ):
                    raise
        state = None
        while time.monotonic() < deadline:
            state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get("State")
            if state not in _ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(f"environment {env_id} never left {state!r} during cleanup")
    for profile in _items(
        ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
    ):
        cp_id = profile["Id"]
        for version in _items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id, ConfigurationProfileId=cp_id
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=120):
    """Start a deployment and poll GetDeployment until it is COMPLETE.

    StartConfigurationSession is refused ResourceNotFoundException until a deployment completes.
    """
    number = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
    )["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    final = None
    while time.monotonic() < deadline:
        final = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=number
        )
        if final.get("State") in _DEPLOYMENT_TERMINAL:
            assert final["State"] == "COMPLETE", (
                f"deployment {number} settled at {final['State']!r}, expected 'COMPLETE'"
            )
            return final
        time.sleep(1.0)
    raise AssertionError(
        f"deployment {number} never reached a terminal state within {timeout_s}s; "
        f"last read was {final!r}"
    )


def _error_response(fn):
    """The full botocore error response for a call that MUST fail; raises if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f"the call was expected to be REJECTED but SUCCEEDED, returning {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A garbage poll token is refused BadRequestException with Problem='Corrupted', an empty
    token is a different refusal with no Details, and a live session minted before both still
    serves its configuration.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    payload = b'{"token":"probe"}'

    app_id = ac.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=payload,
        ContentType="application/json",
    )["VersionNumber"]
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version)

    # A live, working session, minted BEFORE the rejections so it can be re-read after them.
    live = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_id,
    )["InitialConfigurationToken"]
    assert live, "StartConfigurationSession returned no InitialConfigurationToken"

    # --- Break exactly one thing: present a token that is not one.
    garbage = ctx.unique_name("sim2real-behav-not-a-token-")
    corrupted = _error_response(lambda: acd.get_latest_configuration(ConfigurationToken=garbage))
    assert corrupted["Error"]["Code"] == "BadRequestException", (
        f"a corrupted token must be rejected BadRequestException, got "
        f"{corrupted['Error']['Code']!r} ({corrupted['Error'].get('Message')!r})"
    )
    assert corrupted["Error"]["Message"] == "Token not valid", (
        f'expected the exact BadRequestException message AWS returns, got {corrupted["Error"]["Message"]!r}'
    )
    assert corrupted["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"BadRequestException must be HTTP 400, got "
        f"{corrupted['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    assert corrupted.get("Reason") == "InvalidParameters", (
        f"Reason was {corrupted.get('Reason')!r}, expected 'InvalidParameters'"
    )
    problem = (
        corrupted.get("Details", {}).get("InvalidParameters", {})
        .get("ConfigurationToken", {}).get("Problem")
    )
    assert problem == "Corrupted", (
        f"Details.InvalidParameters.ConfigurationToken.Problem was {problem!r}, expected "
        f"'Corrupted'. Without it a client cannot tell 'restart the session' from 'retry later', "
        f"and BadRequestException alone says both"
    )
    assert "Configuration" not in corrupted and "NextPollConfigurationToken" not in corrupted, (
        f"a rejected poll must deliver neither configuration nor a token; response carried "
        f"{sorted(k for k in corrupted if k != 'ResponseMetadata')!r}"
    )

    # --- An EMPTY token is a validation failure, not a token verdict, so it carries no Details.
    absent = _error_response(lambda: acd.get_latest_configuration(ConfigurationToken=""))
    assert absent["Error"]["Code"] == "BadRequestException", (
        f"an empty token must be rejected BadRequestException, got "
        f"{absent['Error']['Code']!r}"
    )
    assert absent["Error"]["Message"] == "ConfigurationToken must be provided. Use the StartConfigurationSession API to obtain an InitialConfigurationToken", (
        f'expected the exact BadRequestException message AWS returns, got {absent["Error"]["Message"]!r}'
    )
    assert "Details" not in absent, (
        f"an empty ConfigurationToken is a missing-parameter refusal and must carry no Details "
        f"union; it carried {absent.get('Details')!r}"
    )
    assert "StartConfigurationSession" in absent["Error"]["Message"], (
        f"the empty-token message must point the caller at StartConfigurationSession; got "
        f"{absent['Error']['Message']!r}"
    )

    # --- Positive control: the live token minted before the rejections is untouched by them.
    served = acd.get_latest_configuration(ConfigurationToken=live)
    body = served["Configuration"].read()
    assert body == payload, (
        f"after two rejected polls the pre-existing session served {body!r}, expected {payload!r} "
        f"-- a rejected request must not disturb an unrelated live session"
    )
    assert served["NextPollConfigurationToken"], (
        "the surviving session must still advance its poll chain"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
