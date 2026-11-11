"""version-label-surfaced-only-with-changed-content."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "version-label-surfaced-only-with-changed-content"
GROUP = 'configuration-data-plane'
SERVICES = ['appconfigdata']

# AppConfig refuses DeleteApplication while any environment or configuration profile survives, and
# DeleteConfigurationProfile while any hosted version survives, so teardown runs bottom-up.

_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


def _items(pages):
    """Flatten an AppConfig paginator's pages into one list of items; every page is read so no
    child survives a parent delete.
    """
    return [item for page in pages for item in page.get("Items", [])]


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and all its children bottom-up; raise if the purge cannot finish."""
    try:
        environments = _items(
            ac.get_paginator("list_environments").paginate(ApplicationId=app_id)
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for env in environments:
        env_id = env["Id"]
        # Per environment, NOT one budget for the whole purge.
        deadline = time.monotonic() + timeout_s
        for dep in _items(
            ac.get_paginator("list_deployments").paginate(
                ApplicationId=app_id, EnvironmentId=env_id
            )
        ):
            if dep.get("State") in _DEPLOYMENT_TERMINAL:
                continue
            try:
                ac.stop_deployment(
                    ApplicationId=app_id,
                    EnvironmentId=env_id,
                    DeploymentNumber=dep["DeploymentNumber"],
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "BadRequestException", "ResourceNotFoundException",
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
    for profile in _items(
        ac.get_paginator("list_configuration_profiles").paginate(ApplicationId=app_id)
    ):
        cp_id = profile["Id"]
        for version in _items(
            ac.get_paginator("list_hosted_configuration_versions").paginate(
                ApplicationId=app_id, ConfigurationProfileId=cp_id
            )
        ):
            ac.delete_hosted_configuration_version(
                ApplicationId=app_id,
                ConfigurationProfileId=cp_id,
                VersionNumber=version["VersionNumber"],
            )
        ac.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    for env in _items(ac.get_paginator("list_environments").paginate(ApplicationId=app_id)):
        ac.delete_environment(ApplicationId=app_id, EnvironmentId=env["Id"])
    ac.delete_application(ApplicationId=app_id)


def _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_id, version, timeout_s=120):
    """Start a deployment and poll GetDeployment until it is COMPLETE.

    Polls an observable condition rather than sleeping: GetLatestConfiguration serves nothing at
    all until a deployment has completed (StartConfigurationSession itself is refused with
    ResourceNotFoundException), so the wait is the precondition of the whole check.
    """
    number = ac.start_deployment(
        ApplicationId=app_id,
        EnvironmentId=env_id,
        DeploymentStrategyId=ds_id,
        ConfigurationProfileId=cp_id,
        ConfigurationVersion=str(version),
    )["DeploymentNumber"]
    deadline = time.monotonic() + timeout_s
    final = None
    while time.monotonic() < deadline:
        final = ac.get_deployment(
            ApplicationId=app_id, EnvironmentId=env_id, DeploymentNumber=number
        )
        if final.get("State") in _DEPLOYMENT_TERMINAL:
            assert final["State"] == "COMPLETE", (
                f"deployment {number} settled at {final['State']!r}, expected 'COMPLETE'"
            )
            return final
        time.sleep(1.0)
    raise AssertionError(
        f"deployment {number} never reached a terminal state within {timeout_s}s; "
        f"last read was {final!r}"
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The content-bearing poll returns the author's VersionLabel and the next unchanged poll omits
    it while still echoing ContentType; an unlabelled hosted version never produces a label.
    """
    ac = ctx.client("appconfig")
    acd = ctx.client("appconfigdata")
    label = "sim2real-behav-label-alpha"
    labelled_payload = b'{"labelled":true}'
    unlabelled_payload = b'{"labelled":false}'

    check_tags = {"sim2real-check": CHECK}
    app_id = ac.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=check_tags
    )["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    env_id = ac.create_environment(
        ApplicationId=app_id, Name=ctx.unique_name("sim2real-behav-env-"), Tags=check_tags
    )["Id"]
    cp_labelled = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cpl-"),
        LocationUri="hosted",
        Tags=check_tags,
    )["Id"]
    cp_plain = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cpp-"),
        LocationUri="hosted",
        Tags=check_tags,
    )["Id"]
    ds_id = ac.create_deployment_strategy(
        Name=ctx.unique_name("sim2real-behav-ds-"),
        DeploymentDurationInMinutes=0,
        GrowthFactor=100,
        FinalBakeTimeInMinutes=0,
        ReplicateTo="NONE",
        Tags=check_tags,
    )["Id"]
    ctx.on_cleanup(lambda: ac.delete_deployment_strategy(DeploymentStrategyId=ds_id))

    labelled = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_labelled,
        Content=labelled_payload,
        ContentType="application/json",
        VersionLabel=label,
    )
    assert labelled.get("VersionLabel") == label, (
        f"the control plane stored the label as {labelled.get('VersionLabel')!r}, not {label!r}; "
        f"the data-plane assertions below would be grading the wrong value"
    )
    plain = ac.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_plain,
        Content=unlabelled_payload,
        ContentType="application/json",
    )
    assert not plain.get("VersionLabel"), (
        f"an unlabelled hosted version came back carrying {plain.get('VersionLabel')!r}"
    )
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_labelled, labelled["VersionNumber"])
    _deploy_and_wait_complete(ac, app_id, env_id, ds_id, cp_plain, plain["VersionNumber"])

    # --- The content-bearing poll carries the label the author set, verbatim.
    session = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_labelled,
    )["InitialConfigurationToken"]
    served = acd.get_latest_configuration(ConfigurationToken=session)
    body = served["Configuration"].read()
    assert body == labelled_payload, (
        f"the first poll served {body!r}, expected {labelled_payload!r}"
    )
    assert served.get("VersionLabel") == label, (
        f"the content-bearing poll returned VersionLabel {served.get('VersionLabel')!r}, expected "
        f"{label!r} -- a client uses this to confirm it is running the build it was told to run"
    )
    assert served["ContentType"] == "application/json", served.get("ContentType")

    # --- The unchanged poll of the SAME session omits the label entirely, while still echoing
    #     ContentType. Absence is the assertion: a synthesised label is the failure mode.
    unchanged = acd.get_latest_configuration(
        ConfigurationToken=served["NextPollConfigurationToken"]
    )
    unchanged_body = unchanged["Configuration"].read()
    assert unchanged_body == b"", (
        f"nothing was deployed between the polls, so the payload must be empty; got "
        f"{len(unchanged_body)} bytes ({unchanged_body[:64]!r})"
    )
    assert "VersionLabel" not in unchanged, (
        f"an unchanged poll must carry NO VersionLabel; it carried "
        f"{unchanged.get('VersionLabel')!r}. A client that reads the label off every poll would "
        f"see a version change where none happened"
    )
    assert unchanged["ContentType"] == "application/json", (
        f"ContentType must still be echoed on an unchanged poll, got "
        f"{unchanged.get('ContentType')!r} -- measured against real AWS, and the assertion the "
        f"shipped empty-when-unchanged check left as UNVERIFIED"
    )

    # --- An unlabelled hosted version never produces a label, however it is polled. This is the
    #     control that makes the presence assertion above attributable to the label, not to the
    #     poll carrying content.
    plain_session = acd.start_configuration_session(
        ApplicationIdentifier=app_id,
        EnvironmentIdentifier=env_id,
        ConfigurationProfileIdentifier=cp_plain,
    )["InitialConfigurationToken"]
    plain_served = acd.get_latest_configuration(ConfigurationToken=plain_session)
    plain_body = plain_served["Configuration"].read()
    assert plain_body == unlabelled_payload, (
        f"the unlabelled profile served {plain_body!r}, expected {unlabelled_payload!r}"
    )
    assert "VersionLabel" not in plain_served, (
        f"a content-bearing poll of an UNLABELLED hosted version must carry no VersionLabel; it "
        f"carried {plain_served.get('VersionLabel')!r}; a version without a label has none to "
        f"report, and the version NUMBER is never sent in its place"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
