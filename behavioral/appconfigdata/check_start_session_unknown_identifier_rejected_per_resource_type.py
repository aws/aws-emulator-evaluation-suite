"""start-session-unknown-identifier-rejected-per-resource-type."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-session-unknown-identifier-rejected-per-resource-type"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfigdata']

# AppConfig teardown must go bottom-up: DeleteApplication is refused while any environment or
# configuration profile survives, and DeleteConfigurationProfile while any hosted version survives.

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


def _items(pages):
    """Flatten an AppConfig paginator's pages into one list of items.

    A parent delete is refused while any child survives, so a first-page-only purge would leak.
    """
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and everything beneath it, bottom-up; raise if it cannot finish."""
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
        # Per environment, NOT one budget for the whole purge.
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

    Polls an observable condition rather than sleeping: GetLatestConfiguration serves nothing at
    all until a deployment has completed (StartConfigurationSession itself is refused with
    ResourceNotFoundException), so the wait is the precondition of the whole check.
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
    """The full botocore error response for a call that MUST fail; raises on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f"the call was expected to be REJECTED but SUCCEEDED, returning {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartConfigurationSession with one unknown identifier fails ResourceNotFoundException/404.
    ResourceType and ReferencedBy name the broken member, no token is returned, and the session
    with all three identifiers correct serves the deployed configuration.

    Reference: https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_appconfigdata_StartConfigurationSession.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    payload = b'{"identifier":"present"}'

    app_id = ac.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags={"sim2real": "audit"}
    )["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-env-"),
        Tags={"sim2real": "audit"},
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags={"sim2real": "audit"},
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags={"sim2real": "audit"},
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))
    version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=payload,
        ContentType="application/json",
    )["VersionNumber"]
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version)

    missing = ctx.unique_name("sim2real-behav-absent-")
    good = {
        "ApplicationIdentifier": app_id,
        "EnvironmentIdentifier": env_id,
        "ConfigurationProfileIdentifier": cp_id,
    }

    # (a) the specific error code, and the identity of the resource, per broken member.
    for member, resource_type in (
        ("ApplicationIdentifier", "Application"),
        ("EnvironmentIdentifier", "Environment"),
        ("ConfigurationProfileIdentifier", "ConfigurationProfile"),
    ):
        request = dict(good, **{member: missing})
        response = _error_response(lambda: acd.start_configuration_session(**request))
        code = response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"an unknown {member} must be rejected ResourceNotFoundException, got {code!r} "
            f"({response['Error'].get('Message')!r})"
        )
        message = response["Error"].get("Message", "")
        assert message == f"{resource_type} not found", f"{member}: message was {message!r}"
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
            f"{member}: ResourceNotFoundException must be HTTP 404, got "
            f"{response['ResponseMetadata']['HTTPStatusCode']!r}"
        )
        assert response.get("ResourceType") == resource_type, (
            f"{member}: ResourceType was {response.get('ResourceType')!r}, expected "
            f"{resource_type!r} -- the error must name WHICH resource was missing, or a client "
            f"cannot tell a typo in the application from a typo in the profile"
        )
        assert response.get("ReferencedBy") == {member: missing}, (
            f"{member}: ReferencedBy was {response.get('ReferencedBy')!r}, expected "
            f"{{{member!r}: {missing!r}}} -- it must map the offending request member to the "
            f"value that was sent"
        )
        # (b) the effect is ABSENT: the rejected call minted no usable session.
        assert "InitialConfigurationToken" not in response, (
            f"{member}: a rejected StartConfigurationSession must not return a token; response "
            f"carried {sorted(k for k in response if k != 'ResponseMetadata')!r}"
        )

    # (c) the positive control, in this same file: all three correct and the session works
    #     end to end, so the four rejections above are attributable to the one broken member.
    session = acd.start_configuration_session(**good)
    token = session["InitialConfigurationToken"]
    assert token, "the control session returned no InitialConfigurationToken"
    served = acd.get_latest_configuration(ConfigurationToken=token)
    body = served["Configuration"].read()
    assert body == payload, (
        f"the control session served {body!r}, expected {payload!r} -- if this fails the setup "
        f"was broken and the rejections above prove nothing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
