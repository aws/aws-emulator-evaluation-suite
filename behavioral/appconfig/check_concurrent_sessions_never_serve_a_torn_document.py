"""concurrent-sessions-never-serve-a-torn-document."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-sessions-never-serve-a-torn-document"
GROUP = 'concurrency'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-concurrent-sessions"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_WORKERS = 16
# Named so the runner reads it as a declared deadline: it only recognises a name
# ending in timeout_s/deadline_s/budget_s/wait_s, and a name it cannot read leaves the suite
# judged at the 300s light ceiling.
_SESSION_RACE_TIMEOUT_S = 420

# Teardown helpers. With AppConfig deletion protection enabled (GetAccountSettings), an environment
# or profile that served the data plane recently is refused with BadRequestException unless
# DeleteEnvironment / DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS".


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


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=300):
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


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """While a deployment switches the served configuration from v1 to v2, sixteen concurrent
    appconfigdata sessions each receive a byte-exact whole version and a distinct session token:
    the served document is atomic and never partial, merged or truncated.
    """
    ac = ctx.client("appconfig")
    v1_bytes = b'{"tier":"one","pad":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    v2_bytes = b'{"tier":"two"}'
    assert len(v1_bytes) != len(v2_bytes), "the two versions must differ in LENGTH as well as bytes"

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
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

    v1 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v1_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    v2 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=v2_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert (v1, v2) == (1, 2), f"hosted version numbering: got {v1!r}, {v2!r}"

    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, v1)

    def _one_session(worker: int, timeout_s=_SESSION_RACE_TIMEOUT_S):
        """Open an independent session and poll it until it is served a non-empty payload.

        Each worker builds its own appconfigdata client: botocore clients are not documented
        thread-safe, and sharing one would make a token collision unfalsifiable — the thing this
        check exists to detect.
        """
        acd = ctx.client("appconfigdata")
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                resp = acd.get_latest_configuration(ConfigurationToken=token)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ThrottlingException":
                    raise
                time.sleep(2.0)
                continue
            body = resp["Configuration"].read()
            if body:
                return worker, token, body
            token = resp.get("NextPollConfigurationToken", token)
            time.sleep(1.0)
        raise AssertionError(
            f"worker {worker} was never served a non-empty payload within {timeout_s}s"
        )

    # The switch: v2 goes out all-at-once WHILE the sixteen sessions are opening.
    with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS + 1) as pool:
        switch = pool.submit(
            _deploy_and_wait_complete, ac, app_id, env_id, ds_id, cp_id, v2
        )
        readers = [pool.submit(_one_session, i) for i in range(_WORKERS)]
        results = [f.result() for f in readers]
        switch.result()

    payloads = [body for _, _, body in results]
    tokens = [token for _, token, _ in results]

    torn = [p for p in payloads if p not in (v1_bytes, v2_bytes)]
    assert not torn, (
        f"a session was served a payload that is neither hosted version — torn or merged "
        f"documents: {[p[:64] for p in torn]!r}"
    )
    assert len(payloads) == _WORKERS, (
        f"only {len(payloads)!r} of {_WORKERS} concurrent sessions were served a payload"
    )
    collisions = len(tokens) - len(set(tokens))
    assert collisions == 0, (
        f"StartConfigurationSession handed the same InitialConfigurationToken to {collisions!r} "
        f"pairs of concurrent callers; a shared token lets one caller advance another's session"
    )

    # After the switch has completed, every NEW session must see v2 — the deployment is not
    # merely 'started', it settled, and the settled answer is one specific version.
    #
    # Polled, and each attempt opens a NEW session. The appconfigdata data plane can lag a
    # deployment reaching COMPLETE by a few seconds, so a single read can race the switch and
    # return version 1. Chaining the
    # next-poll token instead would hit the session's own minimum poll interval and be refused
    # "Request too early". The assertion below is unchanged by the loop: a payload that never
    # becomes version 2 still fails, reporting what was actually served.
    acd = ctx.client("appconfigdata")
    settle_deadline = time.monotonic() + 240
    served = None
    while True:
        settle_token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        served = acd.get_latest_configuration(ConfigurationToken=settle_token)[
            "Configuration"
        ].read()
        if served == v2_bytes or time.monotonic() >= settle_deadline:
            break
        time.sleep(3.0)
    assert served == v2_bytes, (
        f"after the deployment reached COMPLETE a fresh session must be served version 2's exact "
        f"bytes; got {served!r}"
    )
    assert served != v1_bytes, "the data plane is still serving version 1 after the switch"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
