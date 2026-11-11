"""session-against-deleted-environment-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-against-deleted-environment-rejected"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-deleted-environment"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_REFUSAL_TIMEOUT_S = 300

# Teardown helpers. AppConfig deletion protection can be enabled account-wide (GetAccountSettings),
# so DeleteEnvironment and DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS"; the
# setting itself is not asserted.


def _error_code(fn):
    """Return the botocore Error.Code if fn() raises ClientError.

    Raises on unexpected SUCCESS rather than returning a falsy sentinel: an emulator that accepts
    input real AWS refuses is the strongest signal available, and returning "" would turn it into
    an error-code mismatch that reads like a naming difference.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(
        "the call under test SUCCEEDED where real AWS refuses it — this is an "
        "over-permissiveness failure, not an error-code mismatch"
    )


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=240):
    """Delete an application and everything beneath it, bottom-up. Raises rather than leaking."""
    try:
        environments = _purge_items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    for env in environments:
        env_id = env["Id"]
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        ):
            if dep.get("State") in _TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in (
                    "BadRequestException",
                    "ResourceNotFoundException",
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
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
    ):
        cp_id = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id, ConfigurationProfileId=cp_id
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            DeletionProtectionCheck="BYPASS",
        )
    for env in _purge_items(
        ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
    ):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=240):
    """Start a deployment and poll until COMPLETE. Deliberately NOT tolerant of ROLLED_BACK."""
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
        Tags=_TAGS,
    )["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if last.get("State") in _TERMINAL:
            break
        time.sleep(2.0)
    assert last is not None and last.get("State") == "COMPLETE", (
        f"deployment {dep_num} of version {version} did not reach COMPLETE within "
        f"{timeout_s}s; last state {(last or {}).get('State')!r}"
    )
    return dep_num


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=240):
    """Poll FRESH configuration sessions until one is served exactly `expect`; return the
    (token, payload) pair of the last attempt either way.

    A bounded poll on an observable condition, not a sleep standing in for one. MEASURED on real
    AWS: the appconfigdata data plane lags a deployment reaching COMPLETE by a few seconds, so a
    single read races the switch. Each attempt opens a NEW session rather than chaining next-poll
    tokens, because a next-poll token presented before the session's own NextPollIntervalInSeconds
    is refused outright ("Request too early"). The token is returned because this check needs a
    capability minted BEFORE the deletion; the caller still asserts on the payload, so a payload
    that never becomes `expect` fails with what was actually served.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        body = acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()
        if body == expect or time.monotonic() >= deadline:
            return token, body
        time.sleep(3.0)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Deleting a deployed environment withdraws it from the data plane (polled: it lags the control
    plane): StartConfigurationSession and a pre-deletion token get ResourceNotFoundException, while
    a sibling environment serving the same version keeps its exact bytes.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    payload = b'{"shared":"between-both-environments"}'

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    doomed_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-doomed-"), Tags=_TAGS
    )["Id"]
    sibling_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-sibling-"), Tags=_TAGS
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

    # --- Full valid setup: BOTH environments deploy the same version and BOTH serve it. These two
    #     successful serves are the barrier the refusal is measured against.
    _deploy_and_wait_complete(ac, app_id, doomed_id, ds_id, cp_id, version)
    _deploy_and_wait_complete(ac, app_id, sibling_id, ds_id, cp_id, version)
    pre_token, doomed_body = _serve_until(acd, app_id, doomed_id, cp_id, expect=payload)
    assert doomed_body == payload, (
        f"the environment under test must serve the deployed bytes BEFORE it is deleted, or the "
        f"refusal afterwards proves nothing; got {doomed_body!r}"
    )
    _, sibling_body = _serve_until(acd, app_id, sibling_id, cp_id, expect=payload)
    assert sibling_body == payload, (
        f"the sibling environment must serve the deployed bytes too; got {sibling_body!r}"
    )

    # --- Break exactly one thing: delete that one environment. Nothing else changes.
    ac.delete_environment(
        ApplicationId=app_id, EnvironmentId=doomed_id, DeletionProtectionCheck="BYPASS"
    )
    gone_code = None
    deadline = time.monotonic() + _REFUSAL_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            ac.get_environment(ApplicationId=app_id, EnvironmentId=doomed_id)
        except ClientError as exc:
            gone_code = exc.response.get("Error", {}).get("Code")
            break
        time.sleep(2.0)
    assert gone_code == "ResourceNotFoundException", (
        f"GetEnvironment on the deleted environment must answer ResourceNotFoundException, got "
        f"{gone_code!r}"
    )

    # --- Effect absent on the CONTROL plane: it is gone from the paginated listing, and only it.
    #     Paginated because the account may hold other environments and one page is not a bound.
    env_ids = [
        e["Id"]
        for e in _purge_items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    ]
    assert doomed_id not in env_ids, (
        f"the deleted environment is still listed under the application: {env_ids!r}"
    )
    assert sibling_id in env_ids, (
        f"the sibling environment disappeared along with its neighbour: {env_ids!r}"
    )

    # --- The refusal on the DATA plane, reached by polling for it rather than assumed instant.
    session_code = None
    deadline = time.monotonic() + _REFUSAL_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            acd.start_configuration_session(
                ApplicationIdentifier=app_id,
                EnvironmentIdentifier=doomed_id,
                ConfigurationProfileIdentifier=cp_id,
            )
        except ClientError as exc:
            session_code = exc.response.get("Error", {}).get("Code")
            break
        time.sleep(5.0)
    assert session_code == "ResourceNotFoundException", (
        f"StartConfigurationSession for a deleted environment must be refused with "
        f"ResourceNotFoundException within {_REFUSAL_TIMEOUT_S}s, got {session_code!r} — an "
        f"emulator that keeps serving a deleted environment is over-permissive here, and one that "
        f"answers BadRequestException conflates a missing resource with a malformed request"
    )

    # --- And the capability minted before the deletion stops working too: a token is not a
    #     permanent grant on withdrawn state.
    token_code = None
    deadline = time.monotonic() + _REFUSAL_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            acd.get_latest_configuration(ConfigurationToken=pre_token)
        except ClientError as exc:
            token_code = exc.response.get("Error", {}).get("Code")
            break
        time.sleep(5.0)
    assert token_code == "ResourceNotFoundException", (
        f"a configuration token minted before the environment was deleted must stop serving with "
        f"ResourceNotFoundException, got {token_code!r}"
    )

    # --- The positive control, in the same file: the sibling still serves the exact bytes on a
    #     brand-new session, so the refusal is scoped to the deleted environment and is not an
    #     outage of the application, the profile, or the endpoint.
    _, sibling_after = _serve_until(acd, app_id, sibling_id, cp_id, expect=payload)
    assert sibling_after == payload, (
        f"the sibling environment must still serve the deployed bytes after its neighbour was "
        f"deleted; got {sibling_after!r}"
    )
    assert _error_code(
        lambda: ac.get_environment(ApplicationId=app_id, EnvironmentId=doomed_id)
    ) == "ResourceNotFoundException", "the deleted environment reappeared on the control plane"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
