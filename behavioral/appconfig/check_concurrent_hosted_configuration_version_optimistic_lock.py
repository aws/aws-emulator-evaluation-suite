"""concurrent-hosted-configuration-version-optimistic-lock."""
from __future__ import annotations

import time

import concurrent.futures

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-hosted-configuration-version-optimistic-lock"
GROUP = 'concurrency'
SERVICES = ['appconfig']

# AppConfig teardown ORDER is load-bearing: DeleteApplication is refused while any environment or
# configuration profile survives, and DeleteConfigurationProfile is refused while any hosted
# configuration version survives. A bare DeleteApplication teardown raises BadRequestException, and
# because the runner swallows teardown exceptions the application tree would leak while the check
# passed. Bottom-up is the only order AppConfig accepts.

def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items.

    Teardown reads every page, not just the first: AppConfig refuses a parent delete while any child
    survives, so a first-page-only purge would leak the tree.
    """
    return [item for page in pages for item in page.get("Items", [])]


_PURGE_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_PURGE_ENV_TRANSITIONAL = ("Deploying", "RollingBack")

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-concurrent-hosted-configuration-version-optimistic-lock"}


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and everything beneath it, bottom-up.

    Raises rather than leaking quietly: a purge that cannot finish is a real failure, even though
    the runner will swallow it.
    """
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
        # Per environment, not one budget for the whole purge: each environment gets the full wait.
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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers supplying the same LatestVersionNumber: exactly one wins, rest get ConflictException
    naming the taken version or the moved-on latest version."""
    ac = ctx.client("appconfig")
    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    profile_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]

    base = ac.create_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, Content=b"base", ContentType="text/plain"
    )
    base_version = base["VersionNumber"]

    n_racers = 5

    def racer(i):
        return ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            Content=f"racer-{i}".encode(),
            ContentType="text/plain",
            LatestVersionNumber=base_version,
        )

    # Fire all racers at once and capture each outcome (result or exception) in
    # submission order, so we can assert on the distribution of winners/losers.
    with concurrent.futures.ThreadPoolExecutor(max_workers=n_racers) as ex:
        futures = [ex.submit(racer, i) for i in range(n_racers)]
        results = []
        for fut in futures:
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001 — captured for assertion
                results.append(exc)

    n_successes = sum(1 for r in results if not isinstance(r, BaseException))
    error_codes = [
        r.response.get("Error", {}).get("Code")
        for r in results
        if isinstance(r, ClientError)
    ]

    assert n_successes == 1, f"expected exactly 1 winner, got {n_successes} (codes={error_codes})"
    assert len(error_codes) == n_racers - 1, f"expected {n_racers - 1} losers, got {error_codes}"
    assert all(code == "ConflictException" for code in error_codes), error_codes
    error_messages = [
        r.response.get("Error", {}).get("Message")
        for r in results
        if isinstance(r, ClientError)
    ]
    # A loser racing the winner's write reads the version as taken; one arriving after the winner
    # committed reads the latest version as moved on. Which a loser gets depends on its timing.
    taken = f"Hosted configuration version {base_version + 1} already exists"
    moved_on = f"Expected latest version {base_version} does not match actual latest version {base_version + 1}"
    for message in error_messages:
        expected = taken if (message or "").endswith("already exists") else moved_on
        assert message == expected, error_messages

    # The winner must have advanced the version exactly one step past the base.
    winner_idx = next(i for i, r in enumerate(results) if not isinstance(r, BaseException))
    winners = [r for r in results if not isinstance(r, BaseException)]
    assert winners[0]["VersionNumber"] == base_version + 1, (
        f"winner version {winners[0]['VersionNumber']} != {base_version + 1}"
    )

    # Independent read at the destination: the racers' own create responses are not
    # proof the winner was actually persisted, only that the service echoed it back.
    # Confirm via list that exactly base_version and base_version+1 exist (no lost
    # winner, no phantom extra version from a loser that was silently accepted too),
    # and via get that the persisted content is the specific racer that won -- not
    # merely *a* version, but *this* version's bytes.
    listed = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=profile_id
    )
    version_numbers = {item["VersionNumber"] for item in listed["Items"]}
    assert version_numbers == {base_version, base_version + 1}, version_numbers

    persisted = ac.get_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        VersionNumber=base_version + 1,
    )
    expected_content = f"racer-{winner_idx}".encode()
    actual_content = persisted["Content"].read()
    assert actual_content == expected_content, (
        f"persisted content {actual_content!r} != winning racer's {expected_content!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
