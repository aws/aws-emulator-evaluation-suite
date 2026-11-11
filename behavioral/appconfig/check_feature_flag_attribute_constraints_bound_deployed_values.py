"""feature-flag-attribute-constraints-bound-deployed-values."""
from __future__ import annotations

import copy
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-flag-attribute-constraints-bound-deployed-values"
GROUP = 'feature-flags'
SERVICES = ['appconfig']


_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-flag-constraints"}
_FF_TYPE = "AWS.AppConfig.FeatureFlags"
_FF_INVALID_MESSAGE = "Error invoking extension AppConfig Feature Flags Helper: Invalid 'Content' data"
_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")
_MINIMUM = 10
_MAXIMUM = 90
_IN_RANGE = 50
# Deliberately above _MAXIMUM and below the relaxed maximum, so the SAME literal is refused under
# one constraint and accepted under the other.
_OUT_OF_RANGE = 180
_RELAXED_MAXIMUM = 200
_ENUM_VALUES = ["alpha", "beta"]
_OFF_ENUM = "gamma"


def _error(fn):
    """Return the botocore (Error.Code, Error.Message) if fn() raises ClientError. An unexpected
    SUCCESS raises: accepting a document AWS refuses is over-permissiveness, not a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
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
        # BYPASS: account-level deletion protection would otherwise block these deletes.
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


def _flag_document(maximum, percent, tierlabel):
    """An AWS.AppConfig.FeatureFlags authoring document with one constrained number attribute and
    one constrained string attribute, parameterised so each negative differs in one field."""
    return {
        "version": "1",
        "flags": {
            "discount": {
                "name": "discount",
                "attributes": {
                    "percent": {
                        "constraints": {
                            "type": "number",
                            "minimum": _MINIMUM,
                            "maximum": maximum,
                        }
                    },
                    "tierlabel": {
                        "constraints": {"type": "string", "enum": list(_ENUM_VALUES)}
                    },
                },
            }
        },
        "values": {
            "discount": {"enabled": True, "percent": percent, "tierlabel": tierlabel}
        },
    }


def _encode(document):
    return json.dumps(document, sort_keys=True).encode("utf-8")


def _version_numbers(ac, app_id, cp_id):
    return sorted(
        v["VersionNumber"]
        for v in _purge_items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id, ConfigurationProfileId=cp_id
            )
        )
    )


def _serve_until(acd, app_id, env_id, cp_id, predicate, timeout_s=180):
    """Poll FRESH configuration sessions until `predicate(body)` holds; return the last body either
    way. A new session each time, because a next-poll token presented before the session's
    NextPollIntervalInSeconds is refused."""
    deadline = time.monotonic() + timeout_s
    while True:
        token = acd.start_configuration_session(
            ApplicationIdentifier=app_id,
            EnvironmentIdentifier=env_id,
            ConfigurationProfileIdentifier=cp_id,
        )["InitialConfigurationToken"]
        body = acd.get_latest_configuration(ConfigurationToken=token)["Configuration"].read()
        if predicate(body) or time.monotonic() >= deadline:
            return body
        time.sleep(3.0)


def _resolves_percent(body, percent):
    """True if `body` parses as a resolved flag document whose discount.percent is `percent`."""
    if not body:
        return False
    try:
        return json.loads(body).get("discount", {}).get("percent") == percent
    except ValueError:
        return False


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Feature-flag attribute constraints are enforced: a number outside minimum/maximum and a
    string outside its enum are refused with no version consumed, and relaxing the maximum makes
    the same value accepted and served through AppConfig Data.

    Reference: https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-type-reference-feature-flags.html"""
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=_TAGS
    )["Id"]
    cp = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Type=_FF_TYPE,
        Tags=_TAGS,
    )
    cp_id = cp["Id"]
    assert cp["Type"] == _FF_TYPE, (
        f"the profile must be a feature-flags profile for constraints to mean anything; got "
        f"{cp.get('Type')!r}"
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

    valid = _flag_document(_MAXIMUM, _IN_RANGE, _ENUM_VALUES[0])

    # --- BEAT 1, the positive control: the in-range document is accepted.
    good_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=_encode(valid),
        ContentType="application/json",
    )["VersionNumber"]
    assert good_version == 1, f"the first hosted version must be 1, got {good_version!r}"
    # Read it back independently. Byte equality is NOT asserted: AppConfig injects
    # _createdAt/_updatedAt into every flag and value, so the parsed values are the contract.
    stored = json.loads(
        ac.get_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=good_version
        )["Content"].read()
    )
    assert stored["values"]["discount"]["percent"] == _IN_RANGE, (
        f"the accepted document must store the in-range value {_IN_RANGE}; got "
        f"{stored['values']['discount']!r}"
    )
    assert stored["flags"]["discount"]["attributes"]["percent"]["constraints"] == {
        "type": "number",
        "minimum": _MINIMUM,
        "maximum": _MAXIMUM,
    }, (
        f"the number constraint must round-trip exactly as authored; got "
        f"{stored['flags']['discount']['attributes']['percent']!r}"
    )
    assert stored["flags"]["discount"]["attributes"]["tierlabel"]["constraints"]["enum"] == list(
        _ENUM_VALUES
    ), (
        f"the string enum constraint must round-trip exactly as authored; got "
        f"{stored['flags']['discount']['attributes']['tierlabel']!r}"
    )

    # --- BEAT 2, break exactly one thing: the number attribute leaves its range.
    over_max = copy.deepcopy(valid)
    over_max["values"]["discount"]["percent"] = _OUT_OF_RANGE
    assert over_max["flags"] == valid["flags"], (
        "the out-of-range document must differ from the control in the VALUE only, not the "
        "constraint"
    )
    code, code_msg = _error(
        lambda: ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            Content=_encode(over_max),
            ContentType="application/json",
        )
    )
    assert code == "BadRequestException", (
        f"percent={_OUT_OF_RANGE} breaks the declared maximum {_MAXIMUM}, so the create must be "
        f"refused with BadRequestException; got {code!r}. The document is valid against the "
        f"published AWS.AppConfig.FeatureFlags JSON schema, so a target that only runs that schema "
        f"accepts it — that is the failure this asserts."
    )
    assert code_msg == _FF_INVALID_MESSAGE, f"unexpected refusal message: {code_msg!r}"
    assert _version_numbers(ac, app_id, cp_id) == [good_version], (
        f"a refused document must not consume a version number; versions are now "
        f"{_version_numbers(ac, app_id, cp_id)!r}"
    )

    # --- BEAT 3, break exactly one OTHER thing: the string attribute leaves its enum.
    off_enum = copy.deepcopy(valid)
    off_enum["values"]["discount"]["tierlabel"] = _OFF_ENUM
    assert off_enum["values"]["discount"]["percent"] == _IN_RANGE, (
        "the off-enum document must keep the number attribute in range, so the refusal is "
        "attributable to the enum alone"
    )
    code2, code2_msg = _error(
        lambda: ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            Content=_encode(off_enum),
            ContentType="application/json",
        )
    )
    assert code2 == "BadRequestException", (
        f"tierlabel={_OFF_ENUM!r} is outside the declared enum {_ENUM_VALUES!r}, so the create must "
        f"be refused with BadRequestException; got {code2!r}"
    )
    assert code2_msg == _FF_INVALID_MESSAGE, f"unexpected refusal message: {code2_msg!r}"
    assert _version_numbers(ac, app_id, cp_id) == [good_version], (
        f"the second refused document must not consume a version number either; versions are now "
        f"{_version_numbers(ac, app_id, cp_id)!r}"
    )

    # --- BEAT 4, restore: the SAME out-of-range value under a RELAXED maximum is accepted. This is
    #     what proves the constraint refused, not the value.
    relaxed = _flag_document(_RELAXED_MAXIMUM, _OUT_OF_RANGE, _ENUM_VALUES[0])
    assert relaxed["values"] == over_max["values"], (
        "the restore leg must re-send the IDENTICAL values the refusal rejected, changing only the "
        "constraint"
    )
    relaxed_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=_encode(relaxed),
        ContentType="application/json",
    )["VersionNumber"]
    assert relaxed_version == good_version + 1, (
        f"the accepted relaxed document must be the NEXT version number ({good_version + 1}), "
        f"confirming the two refusals consumed none; got {relaxed_version!r}"
    )
    assert _version_numbers(ac, app_id, cp_id) == [good_version, relaxed_version], (
        f"exactly two versions must exist; got {_version_numbers(ac, app_id, cp_id)!r}"
    )

    # --- BEAT 5, the terminal read at the destination: the permitted value reaches clients, through
    #     a different service than the one that stored it.
    dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(relaxed_version),
        Tags=_TAGS,
    )["DeploymentNumber"]
    deadline = time.monotonic() + 180
    settled = None
    while time.monotonic() < deadline:
        settled = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=dep_num
        )
        if settled.get("State") in _TERMINAL:
            break
        time.sleep(2.0)
    assert settled is not None and settled.get("State") == "COMPLETE", (
        f"the relaxed version must deploy: got {(settled or {}).get('State')!r}"
    )
    body = _serve_until(
        acd,
        app_id,
        env_id,
        cp_id,
        predicate=lambda b: _resolves_percent(b, _OUT_OF_RANGE),
    )
    resolved = json.loads(body)
    assert resolved == {
        "discount": {"enabled": True, "percent": _OUT_OF_RANGE, "tierlabel": _ENUM_VALUES[0]}
    }, (
        f"the deployed flag must resolve to exactly the permitted values; served {resolved!r} — "
        f"constraints gate AUTHORING, so once a value is accepted it must be served unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
