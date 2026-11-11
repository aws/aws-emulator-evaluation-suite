"""feature-flag-profile-serves-resolved-flag-document."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-flag-profile-serves-resolved-flag-document"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-feature-flag-resolution"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_FF_TYPE = "AWS.AppConfig.FeatureFlags"


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
        # Account-level deletion protection may be on; BYPASS lets teardown delete fresh resources.
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


def _serve_until(acd, app_id, env_id, cp_id, predicate, timeout_s=240):
    """Poll fresh sessions until the payload satisfies `predicate`; return (payload, ContentType).

    appconfigdata lags a COMPLETE deployment by seconds; a new session per attempt avoids
    the "Request too early" refusal of a next-poll token used before its interval.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        resp = acd.get_latest_configuration(ConfigurationToken=token)
        body = resp["Configuration"].read()
        if predicate(body) or time.monotonic() >= deadline:
            return body, resp.get("ContentType")
        time.sleep(3.0)


def _flag_enabled(body, flag):
    """True if `body` parses as a resolved flag document in which `flag` is enabled."""
    if not body:
        return False
    try:
        return json.loads(body).get(flag, {}).get("enabled") is True
    except ValueError:
        return False


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FeatureFlags profile serves the resolved flag document, not the stored authoring document:
    values projected to top level, disabled flags reduced to {"enabled": false}, bookkeeping pruned.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-type-reference-feature-flags.html
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")

    authored = {
        "version": "1",
        "flags": {
            "alpha": {
                "name": "alpha",
                "attributes": {"limit": {"constraints": {"type": "number"}}},
            },
            "beta": {"name": "beta"},
        },
        "values": {
            "alpha": {"enabled": True, "limit": 7},
            "beta": {"enabled": False},
        },
    }
    authored_bytes = json.dumps(authored).encode()

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-ff-"),
        LocationUri="hosted",
        Type=_FF_TYPE,
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
        Content=authored_bytes,
        ContentType="application/json",
    )["VersionNumber"]
    assert version == 1, f"first hosted version must be 1, got {version!r}"

    stored = json.loads(
        ac.get_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version
        )["Content"].read()
    )
    # The STORED document is the authoring document: it keeps the schema half and the version.
    assert set(stored) == {"flags", "values", "version"}, (
        f"the stored authoring document must keep the flags/values/version envelope, got "
        f"{sorted(stored)!r}"
    )
    assert "_createdAt" in stored["values"]["alpha"], (
        f"AppConfig must inject the _createdAt bookkeeping key into the stored value node, got "
        f"{sorted(stored['values']['alpha'])!r}"
    )

    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version)

    # Poll until alpha is served enabled, then assert the whole document exactly.
    body, content_type = _serve_until(
        acd, app_id, env_id, cp_id, predicate=lambda b: _flag_enabled(b, "alpha")
    )
    served = json.loads(body)

    assert served == {"alpha": {"enabled": True, "limit": 7}, "beta": {"enabled": False}}, (
        f"the resolved flag document must be exactly the projected values with no bookkeeping "
        f"keys; got {served!r}"
    )
    # Each part of that equality, named, so a partial implementation reports which part failed.
    assert served["alpha"]["limit"] == 7, (
        f"the attribute value authored under values.alpha.limit must survive resolution; got "
        f"{served['alpha']!r}"
    )
    assert served["beta"] == {"enabled": False}, (
        f"a disabled flag must resolve to exactly {{'enabled': False}} — no attributes, no "
        f"bookkeeping; got {served['beta']!r}"
    )
    assert "flags" not in served and "values" not in served and "version" not in served, (
        f"the authoring envelope leaked into the served document instead of being projected "
        f"away: {sorted(served)!r}"
    )
    assert "_createdAt" not in served["alpha"] and "_updatedAt" not in served["alpha"], (
        f"the stored bookkeeping keys must be pruned from the served document; got "
        f"{sorted(served['alpha'])!r}"
    )
    assert served != stored, (
        "the served document is byte-identical to the stored authoring document — the service "
        "returned the blob it was given instead of resolving it"
    )
    assert content_type == "application/json", (
        f"a resolved feature-flag document is served as application/json, got {content_type!r}"
    )

    # The resolution is recomputed per version: flip both flags, deploy, and the served doc follows.
    authored["values"]["alpha"] = {"enabled": False, "limit": 9}
    authored["values"]["beta"] = {"enabled": True}
    version2 = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=json.dumps(authored).encode(),
        ContentType="application/json",
    )["VersionNumber"]
    assert version2 == 2, f"second hosted version must be 2, got {version2!r}"
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version2)

    # Poll on one bit (beta enabled) so the poll cannot mask a shape mismatch asserted below.
    body2, _ = _serve_until(
        acd, app_id, env_id, cp_id, predicate=lambda b: _flag_enabled(b, "beta")
    )
    served2 = json.loads(body2)
    assert served2 == {"alpha": {"enabled": False}, "beta": {"enabled": True}}, (
        f"after version 2 the resolved document must reduce the now-disabled alpha to "
        f"{{'enabled': False}} and render beta enabled; got {served2!r}"
    )
    assert "limit" not in served2["alpha"], (
        f"resolution must DROP the attributes of a disabled flag even though the authoring "
        f"document still carries limit=9; got {served2['alpha']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
