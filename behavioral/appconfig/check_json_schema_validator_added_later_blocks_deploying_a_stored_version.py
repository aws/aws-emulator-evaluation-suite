"""json-schema-validator-added-later-blocks-deploying-a-stored-version."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "json-schema-validator-added-later-blocks-deploying-a-stored-version"
GROUP = 'validators'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-validator-at-deploy"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
# The schema demands an integer where the stored version 1 has a string. Chosen so version 1 is
# perfectly valid JSON and perfectly storable, and becomes non-compliant only once the schema exists.
_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "properties": {"replicas": {"type": "integer"}},
    "required": ["replicas"],
}
_NONCOMPLIANT = b'{"replicas":"three"}'
_COMPLIANT = b'{"replicas":3}'


def _error(fn):
    """Return the botocore Error dict if fn() raises ClientError; raise if fn() succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        "the call under test SUCCEEDED where real AWS refuses it — this is an "
        "over-permissiveness failure, not an error-code mismatch"
    )


def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=240):
    """Delete an application and everything beneath it, bottom-up; raise rather than leak."""
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
        # BYPASS: account-level deletion protection may be enabled.
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


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=180):
    """Start a deployment and poll until COMPLETE; ROLLED_BACK fails."""
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
        f"deployment {dep_num} of version {version} did not reach COMPLETE within {timeout_s}s; "
        f"last state {(last or {}).get('State')!r}"
    )
    return dep_num


def _deployment_numbers(ac, app_id, env_id):
    return sorted(
        d["DeploymentNumber"]
        for d in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        )
    )


def _serve_until(acd, app_id, env_id, cp_id, expect, timeout_s=180):
    """Poll fresh configuration sessions until one serves exactly `expect`; return the last payload.

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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A JSON_SCHEMA validator added after a non-compliant version was stored blocks deploying it
    (BadRequestException, no deployment record, version kept), a compliant version still deploys,
    and clearing the validator lets the identical deployment succeed and be served.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-configuration-and-profile-validators.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    schema_text = json.dumps(_SCHEMA)

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )
    cp_id = cp["Id"]
    assert cp.get("Validators", []) == [], (
        f"this check needs a profile that starts with NO validators, so the non-compliant version "
        f"can be stored; got {cp.get('Validators')!r}"
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

    bad_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=_NONCOMPLIANT,
        ContentType="application/json",
    )["VersionNumber"]
    good_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=_COMPLIANT,
        ContentType="application/json",
    )["VersionNumber"]
    assert (bad_version, good_version) == (1, 2), (
        f"hosted version numbering: got {bad_version!r}, {good_version!r} — with no validators on "
        f"the profile BOTH documents must store"
    )

    # Positive control: with no validator, the same version deploys and is served.
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, bad_version)
    served = _serve_until(acd, app_id, env_id, cp_id, expect=_NONCOMPLIANT)
    assert served == _NONCOMPLIANT, (
        f"before the validator exists, version {bad_version} must deploy and be served byte-exactly;"
        f" got {served!r}"
    )
    assert _deployment_numbers(ac, app_id, env_id) == [1], (
        f"exactly one deployment must exist so far; got "
        f"{_deployment_numbers(ac, app_id, env_id)!r}"
    )

    updated = ac.update_configuration_profile(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Validators=[{"Type": "JSON_SCHEMA", "Content": schema_text}],
    )
    assert updated["Validators"] == [{"Type": "JSON_SCHEMA", "Content": schema_text}], (
        f"the validator must be attached before it can gate anything; got "
        f"{updated.get('Validators')!r}"
    )
    live = ac.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert live["Validators"] == [{"Type": "JSON_SCHEMA", "Content": schema_text}], (
        f"an independent read must confirm the validator is on the profile; got "
        f"{live.get('Validators')!r}"
    )

    # The identical StartDeployment is now refused: the validator is consulted at deployment time.
    err = _error(
        lambda: ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(bad_version),
            Tags=_TAGS,
        )
    )
    assert err["Code"] == "BadRequestException", (
        f"a JSON_SCHEMA validator added after the fact must gate StartDeployment of the stored "
        f"non-compliant version {bad_version}, with BadRequestException; got {err['Code']!r} — a target "
        f"that only validates at create time deploys it and leaves the operator's new guard doing "
        f"nothing"
    )

    assert err["Message"] == (
        f"Could not build JSON schema from invalid input:\n {schema_text}.\n Original error message:\n"
        '[message: "instance type (string) does not match any allowed primitive type '
        '(allowed: [\\"integer\\"])" - parent node: /replicas]'
    ), f"unexpected message: {err['Message']!r}"

    assert _deployment_numbers(ac, app_id, env_id) == [1], (
        f"a refused StartDeployment must create NO deployment record; the environment's history is "
        f"now {_deployment_numbers(ac, app_id, env_id)!r}"
    )
    assert (
        ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)["State"] != "Deploying"
    ), "a refused StartDeployment must not leave the environment Deploying"
    unchanged = _serve_until(acd, app_id, env_id, cp_id, expect=_NONCOMPLIANT)
    assert unchanged == _NONCOMPLIANT, (
        f"the refusal must not disturb what is already in service; the data plane served "
        f"{unchanged!r}"
    )
    survivor = ac.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=bad_version
    )["Content"].read()
    assert survivor == _NONCOMPLIANT, (
        f"the refused version must still be STORED — the validator gates deployment, not storage; "
        f"got {survivor!r}"
    )

    # A compliant version deploys through the same validator, so the refusal is about the content.
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, good_version)
    served_good = _serve_until(acd, app_id, env_id, cp_id, expect=_COMPLIANT)
    assert served_good == _COMPLIANT, (
        f"a compliant version must deploy through the attached validator and be served; got "
        f"{served_good!r}"
    )

    cleared = ac.update_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, Validators=[]
    )
    assert cleared.get("Validators", []) == [], (
        f"UpdateConfigurationProfile with an empty Validators list must clear the list; got "
        f"{cleared.get('Validators')!r}"
    )
    reread = ac.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert reread.get("Validators", []) == [], (
        f"an independent read must confirm the validator is gone; got {reread.get('Validators')!r}"
    )
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, bad_version)
    restored = _serve_until(acd, app_id, env_id, cp_id, expect=_NONCOMPLIANT)
    assert restored == _NONCOMPLIANT, (
        f"with the validator cleared the IDENTICAL deployment must succeed and reach the data "
        f"plane; served {restored!r} — if this fails the refusal above was not the validator"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
