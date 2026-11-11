"""binary-configuration-served-byte-exact."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "binary-configuration-served-byte-exact"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfig']

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-binary-payload"}
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_OCTET = "application/octet-stream"

# Teardown helpers. AppConfig deletion protection can be enabled account-wide (GetAccountSettings),
# so DeleteEnvironment and DeleteConfigurationProfile pass DeletionProtectionCheck="BYPASS".


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 4096-byte `application/octet-stream` hosted version holding all 256 byte values is served
    by GetLatestConfiguration byte-identically and with the same ContentType: the store-and-serve
    path must not transcode, escape or NUL-truncate binary configuration data.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")

    # 4096 bytes = every value 0..255, sixteen times over. Contains 0x00, 0xC0 0xC1 (never legal
    # in UTF-8) and the bare continuation bytes 0x80..0xBF, so any UTF-8 decode of it must either
    # raise or substitute.
    payload = bytes(range(256)) * 16
    digest = hashlib.sha256(payload).hexdigest()
    assert len(payload) == 4096, f"payload construction is wrong: {len(payload)!r} bytes"
    assert b"\x00" in payload and b"\xc0\xc1" in payload, "payload lost its adversarial bytes"

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
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

    created = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=payload,
        ContentType=_OCTET,
    )
    version = created["VersionNumber"]
    assert version == 1, f"first hosted version must be 1, got {version!r}"
    assert created["ContentType"] == _OCTET, (
        f"CreateHostedConfigurationVersion must echo ContentType {_OCTET!r}, got "
        f"{created['ContentType']!r}"
    )

    # --- Leg 1: the control plane returns the bytes it was given.
    got = ac.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version
    )
    stored = got["Content"].read()
    assert hashlib.sha256(stored).hexdigest() == digest, (
        f"GetHostedConfigurationVersion mangled the bytes: sha256 "
        f"{hashlib.sha256(stored).hexdigest()!r} over {len(stored)!r} bytes, expected {digest!r} "
        f"over {len(payload)!r}"
    )
    assert got["ContentType"] == _OCTET, (
        f"the stored ContentType changed to {got['ContentType']!r}"
    )

    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version)

    # --- Leg 2: the DATA plane returns the bytes it was given.
    # Polled, opening a NEW session each attempt. The data plane lags the deployment reaching
    # COMPLETE by a few seconds (measured), and re-presenting a next-poll token instead would hit
    # the session's own minimum poll interval and be refused "Request too early". The byte
    # assertions below are unaffected: a payload that never arrives, or arrives wrong, still fails.
    deadline = time.monotonic() + 240
    served = b""
    resp = None
    while True:
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        resp = acd.get_latest_configuration(ConfigurationToken=token)
        served = resp["Configuration"].read()
        if served or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    assert served, "appconfigdata never served the deployed binary configuration"
    assert len(served) == len(payload), (
        f"appconfigdata changed the payload LENGTH: {len(served)!r} bytes served for "
        f"{len(payload)!r} uploaded — a UTF-8 replacement or a JSON escape of the NUL byte both "
        f"present exactly this way"
    )
    assert hashlib.sha256(served).hexdigest() == digest, (
        f"appconfigdata mangled the bytes: sha256 {hashlib.sha256(served).hexdigest()!r}, "
        f"expected {digest!r}; first differing offset "
        f"{next((i for i, (a, b) in enumerate(zip(served, payload)) if a != b), None)!r}"
    )
    assert served == payload, "served payload differs from the uploaded payload"
    assert b"\x00" in served, "NUL bytes were stripped from the served payload"
    assert resp["ContentType"] == _OCTET, (
        f"the served ContentType is {resp['ContentType']!r}, not the {_OCTET!r} the version was "
        f"stored with — the data plane must not re-label a binary configuration"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
