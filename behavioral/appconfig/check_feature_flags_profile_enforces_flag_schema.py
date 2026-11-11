"""feature-flags-profile-enforces-flag-schema."""
from __future__ import annotations

import time

import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "feature-flags-profile-enforces-flag-schema"
GROUP = 'hosted-configuration-version'
SERVICES = ['appconfig']

_FF_INVALID_MESSAGE = "Error invoking extension AppConfig Feature Flags Helper: Invalid 'Content' data"
_FF_TYPE = "AWS.AppConfig.FeatureFlags"
_FREEFORM_TYPE = "AWS.Freeform"
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-feature-flags-schema"}

# AppConfig refuses DeleteApplication while any environment or profile survives, and
# DeleteConfigurationProfile while any hosted version survives, so teardown runs bottom-up.

def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items."""
    return [item for page in pages for item in page.get("Items", [])]


_PURGE_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_PURGE_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and everything beneath it, bottom-up; raise if it cannot finish."""
    try:
        environments = _purge_items(
            ac.get_paginator("list_environments").paginate(
                ApplicationId=app_id,
            )
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    # An environment mid-deployment is undeletable, so stop what is in flight and wait it out.
    for env in environments:
        env_id = env["Id"]
        # One budget per environment, so earlier environments cannot exhaust a shared deadline.
        deadline = time.monotonic() + timeout_s
        for dep in _purge_items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id,
                EnvironmentId=env_id,
            )
        ):
            if dep.get("State") in _PURGE_DEPLOYMENT_TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in (
                    "BadRequestException", "ResourceNotFoundException",
                ):
                    raise
        state = None
        while time.monotonic() < deadline:
            state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get("State")
            if state not in _PURGE_ENV_TRANSITIONAL:
                break
            time.sleep(2.0)
        else:
            raise AssertionError(
                f"environment {env_id} never left {state!r} during cleanup"
            )
    for profile in _purge_items(
        ac.get_paginator("list_configuration_profiles").paginate(
            ApplicationId=app_id,
        )
    ):
        cp_id = profile["Id"]
        for version in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _purge_items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)


def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ff_document(enabled) -> bytes:
    """An AppConfig feature-flag document. `enabled` is a boolean in a valid document;
    passing a string produces the one-field-broken invalid variant."""
    return json.dumps(
        {
            "version": "1",
            "flags": {"newcheckout": {"name": "newcheckout"}},
            "values": {"newcheckout": {"enabled": enabled}},
        }
    ).encode()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A FeatureFlags profile refuses a hosted version whose `enabled` is a string or that lacks
    `version`, storing nothing, while a Freeform profile stores the same invalid bytes verbatim.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-type-reference-feature-flags.html
    """
    ac = ctx.client("appconfig")

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))

    ff_cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-ff-"),
        LocationUri="hosted",
        Type=_FF_TYPE,
        Tags=_TAGS,
    )["Id"]
    free_cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-free-"),
        LocationUri="hosted",
        Type=_FREEFORM_TYPE,
        Tags=_TAGS,
    )["Id"]

    ff_profile = ac.get_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=ff_cp_id
    )
    assert ff_profile["Type"] == _FF_TYPE, (
        f"the feature-flags profile must round-trip Type={_FF_TYPE!r}, got "
        f"{ff_profile.get('Type')!r}"
    )
    assert ff_profile["LocationUri"] == "hosted", ff_profile.get("LocationUri")
    free_profile = ac.get_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=free_cp_id
    )
    assert free_profile["Type"] == _FREEFORM_TYPE, free_profile.get("Type")

    valid = _ff_document(True)
    good_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=ff_cp_id,
        Content=valid,
        ContentType="application/json",
    )["VersionNumber"]
    assert good_version == 1, f"first hosted version must be 1, got {good_version}"

    # AppConfig's feature-flag helper normalises the stored document (it adds bookkeeping
    # keys such as _createdAt/_updatedAt), so the retrieved bytes are NOT asserted equal to
    # the submitted bytes. What must survive is the caller's own semantic content.
    stored = json.loads(
        ac.get_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=ff_cp_id,
            VersionNumber=good_version,
        )["Content"].read()
    )
    assert stored["version"] == "1", stored
    assert "newcheckout" in stored["flags"], stored
    assert stored["values"]["newcheckout"]["enabled"] is True, stored["values"]

    invalid = _ff_document("yes")
    code, code_msg = _error(
        lambda: ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=ff_cp_id,
            Content=invalid,
            ContentType="application/json",
        )
    )
    # BadRequestException is the 400 AppConfig models for invalid configuration content.
    assert code == "BadRequestException", (
        f"a feature-flags profile must refuse a document whose `enabled` is a string; "
        f"got {code!r}"
    )
    assert code_msg == _FF_INVALID_MESSAGE, f"unexpected refusal message: {code_msg!r}"

    versions = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=ff_cp_id
    ).get("Items", [])
    assert [v["VersionNumber"] for v in versions] == [good_version], (
        f"the refused CreateHostedConfigurationVersion must not store a version; "
        f"feature-flags profile now holds {[v['VersionNumber'] for v in versions]}"
    )

    # The same bytes are accepted by the freeform profile, so the rejection is Type-driven.
    free_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=free_cp_id,
        Content=invalid,
        ContentType="application/json",
    )["VersionNumber"]
    assert free_version == 1, free_version
    round_tripped = ac.get_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=free_cp_id,
        VersionNumber=free_version,
    )["Content"].read()
    assert round_tripped == invalid, (
        f"a freeform profile must store the bytes verbatim; got {round_tripped!r}"
    )

    # The schema also requires the top-level `version` key.
    no_version = json.dumps(
        {"flags": {"newcheckout": {"name": "newcheckout"}}, "values": {"newcheckout": {"enabled": True}}}
    ).encode()
    code2, code2_msg = _error(
        lambda: ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=ff_cp_id,
            Content=no_version,
            ContentType="application/json",
        )
    )
    assert code2 == "BadRequestException", (
        f"a feature-flags document with no top-level `version` must be refused; got {code2!r}"
    )
    assert code2_msg == _FF_INVALID_MESSAGE, f"unexpected refusal message: {code2_msg!r}"
    versions_after = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=ff_cp_id
    ).get("Items", [])
    assert [v["VersionNumber"] for v in versions_after] == [good_version], (
        f"the second refusal must also store nothing; got "
        f"{[v['VersionNumber'] for v in versions_after]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
