"""experiment-definition-treatment-config-round-trip."""
from __future__ import annotations

import json
import math

from behavioral_harness import tags

CHECK = "experiment-definition-treatment-config-round-trip"
GROUP = "representation"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-experiment-definition-treatment-config-round-trip"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode names/descriptions and fractional treatment weights survive
    CreateExperimentDefinition -> GetExperimentDefinition exactly, with no
    truncation, re-encoding, or floating point rounding drift."""
    appconfig = ctx.client("appconfig")
    prereqs = _setup_experiment_prereqs(ctx)

    unicode_name = ctx.unique_name("sim2real-appcfg-exp-") + "-Ünïcödé-日本語"
    control_desc = "Contrôle bäseline ⚡ 33.33%"
    treatment_desc = "Tréâtment Δ 変数 33.34%"

    # NOTE: AppConfig stores Weight with single-precision (float32) fidelity
    # internally, so a round-tripped double can differ from the input by a
    # float32-level amount. Measured directly against real AWS: 33.34 comes
    # back as 33.34000015258789 (drift ~1.5e-7). WEIGHT_TOL is set an order
    # of magnitude above that measured drift -- tight enough to still catch
    # a coarser rounding/truncation defect, loose enough not to flake on the
    # genuine float32 storage characteristic.
    WEIGHT_TOL = 1e-5

    created = appconfig.create_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"],
        Name=unicode_name,
        ConfigurationProfileIdentifier=prereqs["profile_id"],
        EnvironmentIdentifier=prereqs["env_id"],
        FlagKey=prereqs["flag_key"],
        Treatments=[
            {"Weight": 33.34, "Description": treatment_desc, "FlagValue": {"Enabled": True}},
        ],
        Control={"Weight": 33.33, "Description": control_desc, "FlagValue": {"Enabled": False}},
        AudienceRule='(eq $country "US")',
        Tags=_TAGS,
    )
    exp_id = created["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_experiment_definition(
            ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id, DeleteType="DESTROY"
        )
    )

    assert created["Name"] == unicode_name, f"name mangled: expected {unicode_name!r} got {created['Name']!r}"
    assert math.isclose(created["Treatments"][0]["Weight"], 33.34, rel_tol=0, abs_tol=WEIGHT_TOL), (
        f"treatment weight drift: expected 33.34 got {created['Treatments'][0]['Weight']!r}"
    )
    assert created["Treatments"][0]["Description"] == treatment_desc, (
        f"treatment description mangled: expected {treatment_desc!r} got {created['Treatments'][0]['Description']!r}"
    )
    assert math.isclose(created["Control"]["Weight"], 33.33, rel_tol=0, abs_tol=WEIGHT_TOL), (
        f"control weight drift: expected 33.33 got {created['Control']['Weight']!r}"
    )
    assert created["Control"]["Description"] == control_desc, (
        f"control description mangled: expected {control_desc!r} got {created['Control']['Description']!r}"
    )

    fetched = appconfig.get_experiment_definition(
        ApplicationIdentifier=prereqs["app_id"], ExperimentDefinitionIdentifier=exp_id
    )
    assert fetched["Name"] == unicode_name, f"name mangled on get: expected {unicode_name!r} got {fetched['Name']!r}"
    assert math.isclose(fetched["Treatments"][0]["Weight"], 33.34, rel_tol=0, abs_tol=WEIGHT_TOL), (
        f"treatment weight drift on get: expected 33.34 got {fetched['Treatments'][0]['Weight']!r}"
    )
    assert fetched["Treatments"][0]["Description"] == treatment_desc, (
        f"treatment description mangled on get: expected {treatment_desc!r} got {fetched['Treatments'][0]['Description']!r}"
    )
    assert math.isclose(fetched["Control"]["Weight"], 33.33, rel_tol=0, abs_tol=WEIGHT_TOL), (
        f"control weight drift on get: expected 33.33 got {fetched['Control']['Weight']!r}"
    )
    assert fetched["Control"]["Description"] == control_desc, (
        f"control description mangled on get: expected {control_desc!r} got {fetched['Control']['Description']!r}"
    )
    # exact round-trip: created and fetched values must match each other precisely
    # (both went through the same float32 storage, so no further drift is allowed)
    assert created["Treatments"][0]["Weight"] == fetched["Treatments"][0]["Weight"], (
        f"treatment weight changed between create response and get: {created['Treatments'][0]['Weight']!r} != {fetched['Treatments'][0]['Weight']!r}"
    )
    assert created["Control"]["Weight"] == fetched["Control"]["Weight"], (
        f"control weight changed between create response and get: {created['Control']['Weight']!r} != {fetched['Control']['Weight']!r}"
    )


def _make_flag_content(flag_key: str) -> bytes:
    return json.dumps(
        {
            "flags": {flag_key: {"name": flag_key}},
            "values": {flag_key: {"enabled": True}},
            "version": "1",
        }
    ).encode("utf-8")


def _setup_experiment_prereqs(ctx, flag_key: str = "expflag") -> dict[str, str]:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-appcfg-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-appcfg-profile-"),
        LocationUri="hosted",
        Type="AWS.AppConfig.FeatureFlags",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=profile_id)
    )

    appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=_make_flag_content(flag_key),
        ContentType="application/json",
    )
    return {"app_id": app_id, "env_id": env_id, "profile_id": profile_id, "flag_key": flag_key}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
