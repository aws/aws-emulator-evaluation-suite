"""ssm-parameter-backed-profile-serves-the-deployed-parameter-version."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-parameter-backed-profile-serves-the-deployed-parameter-version"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfig', 'ssm']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-ssm-parameter-source"}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_VALUE_ONE = "tier-one"
_VALUE_TWO = "tier-two"
_ABSENCE_MULTIPLIER = 3
# Overall bound for an account where IAM propagation is slow.
_SOURCE_BUDGET_S = 600
_ROLE_PROPAGATION_TIMEOUT_S = 300


# DeletionProtectionCheck="BYPASS" because account-level deletion protection may be enabled.


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
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(
            ApplicationId=app_id, EnvironmentId=env["Id"], DeletionProtectionCheck="BYPASS"
        )
    ac.delete_application(ApplicationId=app_id)


def _make_role(ctx, iam, trusted_service, statements):
    """Create a role trusted by one AWS service with one inline policy. Registers cleanup for the
    policy and the role immediately after each create, in LIFO order."""
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trusted_service},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=_TAGLIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn


def _wait_terminal(ac, app_id, env_id, dep_num, timeout_s=240):
    """Poll GetDeployment until the deployment reaches a terminal state. Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if last.get("State") in _TERMINAL:
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"deployment {dep_num} never reached a terminal state within {timeout_s}s; last state "
        f"{(last or {}).get('State')!r}"
    )


def _sample_sessions(acd, app_id, env_id, cp_id, n):
    """Open n independent sessions and return the payload each one is served."""
    out = []
    for _ in range(n):
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        out.append(acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read())
    return out


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=180):
    """Poll fresh sessions until one is served exactly `expect`; return the last payload seen.

    A new session per attempt: a next-poll token used before NextPollIntervalInSeconds is refused.
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
            return body
        time.sleep(3.0)


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A profile backed by an SSM parameter serves the parameter version the deployment named.
    Overwriting the parameter afterwards leaves every session on the deployed value, and only a new
    deployment naming the new version changes what clients are served.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # A name with NO leading slash, so the ssm-parameter:// URI is unambiguous.
    param_name = ctx.unique_name("sim2real-behav-param-")
    param_arn = f"arn:aws:ssm:{ctx.region}:{account}:parameter/{param_name}"

    version_one = ssm.put_parameter(
        Name=param_name, Value=_VALUE_ONE, Type="String", Tags=_TAGLIST
    )["Version"]
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))
    assert version_one == 1, f"a freshly created SSM parameter must be version 1, got {version_one!r}"
    # The expected bytes come from the SOURCE, not from a literal in this file.
    value_one_bytes = ssm.get_parameter(Name=param_name)["Parameter"]["Value"].encode("utf-8")
    assert value_one_bytes == _VALUE_ONE.encode("utf-8"), (
        f"the parameter must hold what it was given; SSM reports {value_one_bytes!r}"
    )

    retrieval_role_arn = _make_role(
        ctx,
        iam,
        "appconfig.amazonaws.com",
        [{"Effect": "Allow", "Action": "ssm:GetParameter", "Resource": param_arn}],
    )

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    location_uri = f"ssm-parameter://{param_name}"

    # AppConfig validates it can assume RetrievalRoleArn at CreateConfigurationProfile time; a fresh
    # role's trust policy may not have propagated yet, which yields
    # `BadRequestException: Error trying to assume role <arn>`, so retry here.
    cp_name = ctx.unique_name("sim2real-behav-cp-")
    cp = None
    attempts_cp = 0
    deadline_cp = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    last_error_cp = None
    while time.monotonic() < deadline_cp:
        attempts_cp += 1
        try:
            cp = ac.create_configuration_profile(
                ApplicationId=app_id,
                Name=cp_name,
                LocationUri=location_uri,
                RetrievalRoleArn=retrieval_role_arn,
                Tags=_TAGS,
            )
            break
        except ClientError as exc:
            last_error_cp = exc.response.get("Error", {})
            if last_error_cp.get("Code") != "BadRequestException" or "assume role" not in (
                last_error_cp.get("Message") or ""
            ):
                raise
            time.sleep(2.0)
    assert cp is not None, (
        f"CreateConfigurationProfile never accepted retrieval role {retrieval_role_arn!r} in "
        f"{attempts_cp!r} attempts over {_ROLE_PROPAGATION_TIMEOUT_S}s; last error {last_error_cp!r}"
    )
    cp_id = cp["Id"]
    assert cp["LocationUri"] == location_uri, (
        f"the profile must record the external source URI it was given; got "
        f"{cp.get('LocationUri')!r}"
    )
    assert cp["RetrievalRoleArn"] == retrieval_role_arn, (
        f"the profile must record the retrieval role AppConfig will assume; got "
        f"{cp.get('RetrievalRoleArn')!r}"
    )
    # An independent read of the profile, through a different operation than the create.
    stored_profile = ac.get_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=cp_id
    )
    assert (stored_profile["LocationUri"], stored_profile["RetrievalRoleArn"]) == (
        location_uri,
        retrieval_role_arn,
    ), (
        f"GetConfigurationProfile must agree about the external source and its role; got "
        f"{stored_profile.get('LocationUri')!r} / {stored_profile.get('RetrievalRoleArn')!r}"
    )
    # The hosted store is EMPTY for this profile — proof that anything served below came from SSM.
    hosted = _purge_items(
        ac.get_paginator("list_hosted_configuration_versions").paginate(
            ApplicationId=app_id, ConfigurationProfileId=cp_id
        )
    )
    assert hosted == [], (
        f"an SSM-backed profile must have no hosted configuration versions, so what the data plane "
        f"serves can only have come from Parameter Store; got {hosted!r}"
    )

    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    # --- BEAT 1: deploy parameter version 1. Bounded retry at FIRST USE of the retrieval role,
    #     because AppConfig cannot read the parameter until the trust policy has propagated and a
    #     not-yet-assumable role produces the same failure a genuinely unreadable source would.
    first = None
    attempts = 0
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    last_error = None
    while time.monotonic() < deadline:
        attempts += 1
        try:
            dep_num = ac.start_deployment(
                ApplicationId=app_id,
                EnvironmentId=env_id,
                DeploymentStrategyId=ds_id,
                ConfigurationProfileId=cp_id,
                ConfigurationVersion=str(version_one),
                Tags=_TAGS,
            )["DeploymentNumber"]
        except ClientError as exc:
            last_error = exc.response.get("Error", {})
            time.sleep(2.0)
            continue
        settled = _wait_terminal(ac, app_id, env_id, dep_num)
        if settled["State"] == "COMPLETE":
            first = settled
            break
        time.sleep(2.0)
    assert first is not None, (
        f"no deployment of SSM parameter version {version_one} reached COMPLETE in {attempts!r} "
        f"attempts over {_ROLE_PROPAGATION_TIMEOUT_S}s, so AppConfig never managed to read the "
        f"external source at all; last error {last_error!r}"
    )
    assert first["ConfigurationVersion"] == str(version_one), (
        f"the deployment must record the SOURCE version it deployed ({version_one}); GetDeployment "
        f"says {first.get('ConfigurationVersion')!r}"
    )
    assert first["ConfigurationLocationUri"] == location_uri, (
        f"the deployment must record the external source it read from; got "
        f"{first.get('ConfigurationLocationUri')!r}"
    )
    # Snapshot the deployment history now, in case the retry loop above needed more than one
    # StartDeployment call — every attempt names the same source version, so this must hold
    # regardless of how many attempts the role's permission propagation cost.
    history_after_first = _purge_items(
        ac.get_paginator("list_deployments").paginate(ApplicationId=app_id, EnvironmentId=env_id)
    )
    assert all(d["ConfigurationVersion"] == str(version_one) for d in history_after_first), (
        f"every deployment record before the overwrite must target source version {version_one}; "
        f"got {[(d['DeploymentNumber'], d['ConfigurationVersion']) for d in history_after_first]!r}"
    )

    # --- The data plane serves the PARAMETER's value. L, the delivery latency used by the absence
    #     window below, is measured from HERE — after the deployment is COMPLETE — so the role
    #     propagation retry above does not inflate it.
    completed_at = time.monotonic()
    served = _serve_until(acd, app_id, env_id, cp_id, expect=value_one_bytes)
    latency_s = max(time.monotonic() - completed_at, 1.0)
    assert served == value_one_bytes, (
        f"an SSM-backed profile must serve the deployed parameter version's value through "
        f"appconfigdata; expected {value_one_bytes!r}, served {served!r}"
    )

    # --- BEAT 2: change the SOURCE behind AppConfig's back.
    version_two = ssm.put_parameter(
        Name=param_name, Value=_VALUE_TWO, Type="String", Overwrite=True
    )["Version"]
    assert version_two == version_one + 1, (
        f"overwriting the parameter must produce the next version ({version_one + 1}); got "
        f"{version_two!r}"
    )
    # Positive control that the mutation LANDED: SSM itself now returns the new value.
    value_two_bytes = ssm.get_parameter(Name=param_name)["Parameter"]["Value"].encode("utf-8")
    assert value_two_bytes == _VALUE_TWO.encode("utf-8"), (
        f"the parameter overwrite must be visible at the source; GetParameter reports "
        f"{value_two_bytes!r}"
    )
    assert value_two_bytes != value_one_bytes, (
        "the two parameter versions must differ, or the freeze assertion below is vacuous"
    )

    # --- BEAT 3, THE POINT: AppConfig deployed version 1, so version 1 is what it keeps serving.
    #     Structural barrier plus a 3L window plus three independent sessions.
    absence_window_s = _ABSENCE_MULTIPLIER * latency_s
    absence_deadline = time.monotonic() + absence_window_s
    while time.monotonic() < absence_deadline:
        during = _sample_sessions(acd, app_id, env_id, cp_id, 1)
        assert during == [value_one_bytes], (
            f"the deployment pinned SSM parameter version {version_one}, so no session may be "
            f"served version {version_two}'s value until a NEW deployment names it; a session was "
            f"served {during!r} (expected {value_one_bytes!r}) within {absence_window_s:.0f}s of "
            f"the overwrite — that is a target resolving LocationUri live instead of honouring the "
            f"deployed version"
        )
        time.sleep(5.0)
    settled_frozen = _sample_sessions(acd, app_id, env_id, cp_id, 3)
    assert set(settled_frozen) == {value_one_bytes}, (
        f"after {absence_window_s:.0f}s (3x the {latency_s:.0f}s delivery latency measured on this "
        f"same wiring) every fresh session must still be served the DEPLOYED parameter version's "
        f"value; got {sorted(set(settled_frozen))!r}"
    )
    # The deployment record has not moved either — compared against the snapshot taken right after
    # BEAT 1, not against an assumed singleton, because BEAT 1's retry loop may have needed more
    # than one attempt.
    history = _purge_items(
        ac.get_paginator("list_deployments").paginate(ApplicationId=app_id, EnvironmentId=env_id)
    )
    assert history == history_after_first, (
        f"mutating the source must neither create a deployment nor rewrite an existing one; the "
        f"environment's deployment history changed from "
        f"{[(d['DeploymentNumber'], d['ConfigurationVersion']) for d in history_after_first]!r} to "
        f"{[(d['DeploymentNumber'], d['ConfigurationVersion']) for d in history]!r}"
    )

    # --- BEAT 4, re-prove delivery: deploying the NEW source version does change what clients get,
    #     so the freeze above was pinning and not a dead data plane.
    dep2 = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version_two),
        Tags=_TAGS,
    )["DeploymentNumber"]
    second = _wait_terminal(ac, app_id, env_id, dep2)
    assert second["State"] == "COMPLETE", (
        f"deploying SSM parameter version {version_two} must succeed; got {second['State']!r}"
    )
    assert second["ConfigurationVersion"] == str(version_two), (
        f"the second deployment must record source version {version_two}; got "
        f"{second.get('ConfigurationVersion')!r}"
    )
    served_two = _serve_until(acd, app_id, env_id, cp_id, expect=value_two_bytes)
    assert served_two == value_two_bytes, (
        f"after deploying source version {version_two} the data plane must serve its value; "
        f"expected {value_two_bytes!r}, served {served_two!r} — if this fails the freeze asserted "
        f"above was a broken retrieval path, not version pinning"
    )
    confirm = _sample_sessions(acd, app_id, env_id, cp_id, 3)
    assert set(confirm) == {value_two_bytes}, (
        f"the new source version must reach EVERY session, not one: three fresh sessions were "
        f"served {sorted(set(confirm))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
