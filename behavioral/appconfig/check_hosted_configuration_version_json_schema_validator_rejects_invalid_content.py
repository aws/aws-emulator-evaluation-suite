"""hosted-configuration-version-json-schema-validator-rejects-invalid-content."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hosted-configuration-version-json-schema-validator-rejects-invalid-content"
GROUP = 'overly-permissive'
SERVICES = ['appconfig']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, HTTP status, Error.Message). A success raises:
    a target that accepts what real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _norm_state(value) -> str:
    """Normalize a state string to bare uppercase letters for comparison.

    GetEnvironment returns PascalCase ("ReadyForDeployment"); GetDeployment returns
    SCREAMING_SNAKE ("COMPLETE")."""
    return str(value or "").replace("_", "").replace("-", "").upper()


def _wait_for_deployment_state(
    ac, app_id, env_id, deployment_number, target_states, timeout_s=180, interval_s=3
):
    targets = {_norm_state(s) for s in target_states}
    deadline = time.time() + timeout_s
    while True:
        last = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )
        if _norm_state(last.get("State")) in targets:
            return last
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for deployment {deployment_number} "
                f"to reach one of {sorted(targets)}; last state={last.get('State')!r}"
            )
        time.sleep(interval_s)


def _wait_for_environment_ready(ac, app_id, env_id, timeout_s=60, interval_s=2):
    """Wait for the environment to return to ReadyForDeployment after a deployment."""
    deadline = time.time() + timeout_s
    while True:
        env = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
        if _norm_state(env.get("State")) == _norm_state("ReadyForDeployment"):
            return env
        if time.time() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for environment {env_id} to return to "
                f"ReadyForDeployment; last state={env.get('State')!r}"
            )
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A JSON_SCHEMA validator round-trips on the profile; conformant content deploys to COMPLETE,
    while StartDeployment of a violating version is refused (400 BadRequestException, exact
    message) and records no deployment.
    """
    ac = ctx.client("appconfig")

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: ac.delete_application(ApplicationId=app_id))

    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-")
    )["Id"]
    ctx.on_cleanup(
        lambda: ac.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    )

    schema = (
        '{"$schema":"http://json-schema.org/draft-04/schema#",'
        '"type":"object",'
        '"properties":{"limit":{"type":"integer"}},'
        '"required":["limit"],'
        '"additionalProperties":false}'
    )
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Validators=[{"Type": "JSON_SCHEMA", "Content": schema}],
    )["Id"]
    ctx.on_cleanup(
        lambda: ac.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=cp_id
        )
    )

    # The validator must round-trip -- it is part of the profile's durable state.
    profile = ac.get_configuration_profile(
        ApplicationId=app_id, ConfigurationProfileId=cp_id
    )
    validators = profile.get("Validators", [])
    assert len(validators) == 1, validators
    assert validators[0]["Type"] == "JSON_SCHEMA", validators
    assert validators[0]["Content"] == schema, validators

    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    # Positive control on the same profile: separates "the validator blocked the bad content"
    # from "every deployment fails".
    good_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"limit":1}',
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: ac.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=good_version
        )
    )
    good_dep_num = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(good_version),
    )["DeploymentNumber"]
    good_final = _wait_for_deployment_state(
        ac, app_id, env_id, good_dep_num, {"COMPLETE", "ROLLED_BACK", "REVERTED"}
    )
    assert _norm_state(good_final["State"]) == _norm_state("COMPLETE"), (
        "positive control failed: schema-conformant configuration did not complete, so a "
        "blocked deployment below would prove nothing about the validator -- state="
        + str(good_final["State"])
    )
    # A second deployment cannot start until the environment leaves its post-deployment
    # transitional state.
    _wait_for_environment_ready(ac, app_id, env_id)

    # "limit" must be an integer; a string violates the schema. CreateHostedConfigurationVersion
    # does not evaluate the validator for a hosted profile, so storing it succeeds.
    bad_version = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=b'{"limit":"not-an-integer"}',
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: ac.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=bad_version
        )
    )

    code, status, message = _error(
        lambda: ac.start_deployment(
            ApplicationId=app_id,
            EnvironmentId=env_id,
            DeploymentStrategyId=ds_id,
            ConfigurationProfileId=cp_id,
            ConfigurationVersion=str(bad_version),
        )
    )
    assert code == "BadRequestException", (
        f"StartDeployment of a schema-violating version must be refused with "
        f"BadRequestException, got {code!r}"
    )
    assert status == 400, f"expected HTTP 400 for the schema-violating deployment, got {status!r}"
    expected_message = f'Could not build JSON schema from invalid input:\n {schema}.\n Original error message:\n[message: "instance type (string) does not match any allowed primitive type (allowed: [\\"integer\\"])" - parent node: /limit]'
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # State unchanged: the refused StartDeployment left no deployment behind and the
    # environment is still ready.
    deployments = [
        d["DeploymentNumber"]
        for page in ac.get_paginator("list_deployments").paginate(
            ApplicationId=app_id, EnvironmentId=env_id
        )
        for d in page.get("Items", [])
    ]
    assert deployments == [good_dep_num], (
        f"the refused StartDeployment must not record a deployment; ListDeployments holds "
        f"{deployments!r}, expected exactly [{good_dep_num}]"
    )
    env_state = ac.get_environment(ApplicationId=app_id, EnvironmentId=env_id).get("State")
    assert _norm_state(env_state) == _norm_state("ReadyForDeployment"), (
        f"the refused StartDeployment moved the environment to {env_state!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
