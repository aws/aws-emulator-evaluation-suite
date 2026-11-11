"""op-contract-getConfiguration."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getConfiguration"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-get-configuration-contract"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetConfiguration returns the exact bytes of the version deployed to the environment, and a
    Configuration identifier that never existed raises BadRequestException.
    """
    appconfig = ctx.client("appconfig")
    deployment = _create_completed_deployment(ctx, appconfig)

    resp = appconfig.get_configuration(
        Application=deployment["app_id"],
        Environment=deployment["env_id"],
        Configuration=deployment["profile_id"],
        ClientId="sim2real-behavioral-client",
    )
    content = resp["Content"].read()
    assert content == deployment["content"], (
        f"expected byte-exact deployed content {deployment['content']!r}, got {content!r}"
    )
    assert resp["ContentType"] == deployment["content_type"], (
        f"expected ContentType {deployment['content_type']!r}, got {resp['ContentType']!r}"
    )

    # error boundary: Configuration identifier does not reference any profile on the
    # app. On real AWS, GetConfiguration's deprecated resolution path reports both "the
    # given Configuration id/name is not well-formed" and "no profile/deployment
    # matches this Application/Environment/Configuration" as BadRequestException
    # (ResourceNotFoundException is not what the deprecated call actually raises for
    # this family of "nothing to serve" conditions). Deleting a real profile is not
    # reliable either: deletion can leave the id resolvable for a short window, so
    # instead derive a same-shaped, syntactically-valid id that was never created by
    # mutating the real (still-live) profile id in place.
    real_profile_id = deployment["profile_id"]
    mutated = real_profile_id[::-1]
    if mutated == real_profile_id:
        last = real_profile_id[-1]
        mutated = real_profile_id[:-1] + ("0" if last != "0" else "1")
    stale_profile_id = mutated

    account = ctx.client("sts").get_caller_identity()["Account"]
    error = _expect_error(
        lambda: appconfig.get_configuration(
            Application=deployment["app_id"],
            Environment=deployment["env_id"],
            Configuration=stale_profile_id,
            ClientId="sim2real-behavioral-client",
        )
    )
    assert error["Code"] == "BadRequestException", (
        f"expected BadRequestException, got {error['Code']!r}"
    )
    assert error["Message"] == (
        f"Configuration Profile with Application Id {deployment['app_id']} and Configuration "
        f"Profile Id {stale_profile_id} could not be found for account {account}."
    ), f"unexpected message for a never-created Configuration id: {error['Message']!r}"



def _expect_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a client error, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_completed_deployment(ctx, appconfig):
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-env-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id))

    strategy_id = appconfig.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100.0,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_deployment_strategy(DeploymentStrategyId=strategy_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    content = b'{"enabled": true}'
    content_type = "application/json"
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType=content_type,
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    started = appconfig.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=strategy_id,
        ConfigurationProfileId=profile_id,
        ConfigurationVersion=str(version_number),
    )
    deployment_number = started["DeploymentNumber"]

    def _probe():
        return appconfig.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=deployment_number
        )

    final = _poll_until(
        _probe, lambda d: d["State"] in ("COMPLETE", "ROLLED_BACK"), timeout_s=120.0, interval_s=3.0
    )
    if final["State"] != "COMPLETE":
        raise AssertionError(f"deployment ended in unexpected state {final['State']}")

    return {
        "app_id": app_id,
        "env_id": env_id,
        "profile_id": profile_id,
        "strategy_id": strategy_id,
        "version_number": version_number,
        "content": content,
        "content_type": content_type,
        "deployment_number": deployment_number,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
