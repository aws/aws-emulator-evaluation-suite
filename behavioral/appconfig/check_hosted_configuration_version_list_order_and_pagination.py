"""hosted-configuration-version-list-order-and-pagination."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hosted-configuration-version-list-order-and-pagination"
GROUP = 'hosted-configuration-version'
SERVICES = ['appconfig']

MAX_PAGES = 20  # bounded: five versions at MaxResults=2 needs three pages
_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-hosted-version-list-order"}

# Teardown is bottom-up: DeleteApplication is refused while any environment or configuration
# profile survives, and DeleteConfigurationProfile while any hosted configuration version does.

def _purge_items(pages):
    """Flatten an AppConfig paginator's pages into one list of items.

    Every page matters: a parent delete is refused while any child survives."""
    return [item for page in pages for item in page.get("Items", [])]


_PURGE_DEPLOYMENT_TERMINAL = ("COMPLETE", "ROLLED_BACK", "REVERTED")
_PURGE_ENV_TRANSITIONAL = ("Deploying", "RollingBack")


def _purge_application(ac, app_id, timeout_s=180):
    """Delete an application and everything beneath it, bottom-up; raises if it cannot finish."""
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
        # Per environment, so time spent on earlier environments cannot starve this wait.
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


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHostedConfigurationVersions honours MaxResults and NextToken, enumerating each version
    exactly once across pages, filters by VersionLabel, omits content, and rejects an unknown profile id.

    Reference: https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_ListHostedConfigurationVersions.html
    """
    ac = ctx.client("appconfig")

    app_id = ac.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _purge_application(ac, app_id))
    cp_id = ac.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]

    # --- Five versions. Exactly one of them carries a label, so the filter has a single
    # correct answer. VersionLabel's pattern is `.*[^0-9].*` (it must contain a non-digit),
    # hence the word-y label rather than a number.
    labelled_version = None
    label = "release-candidate-three"
    created = []
    for n in range(1, 6):
        kwargs = {}
        if n == 3:
            kwargs["VersionLabel"] = label
        version = ac.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            Content=f'{{"n":{n}}}'.encode(),
            ContentType="application/json",
            **kwargs,
        )["VersionNumber"]
        created.append(version)
        if n == 3:
            labelled_version = version
    assert created == [1, 2, 3, 4, 5], (
        f"hosted version numbers must be a dense 1-based sequence, got {created}"
    )
    assert labelled_version == 3, labelled_version

    # --- MaxResults is honoured exactly. The model documents no listing order, so pages are
    # compared as sets of version numbers.
    first_page = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, MaxResults=2
    )
    page_one = [v["VersionNumber"] for v in first_page["Items"]]
    assert len(page_one) == 2, (
        f"MaxResults=2 must return exactly 2 items when 5 exist, got {len(page_one)}: {page_one}"
    )
    assert len(set(page_one)) == 2 and set(page_one) <= set(created), (
        f"page 1 of MaxResults=2 must hold two distinct created versions of {created}; "
        f"got {page_one}"
    )
    assert first_page.get("NextToken"), (
        "3 of 5 versions remain, so NextToken must be present on page 1"
    )

    # --- Paging visits every version exactly once and terminates without a trailing token.
    seen, token, pages = [], None, 0
    while pages < MAX_PAGES:
        pages += 1
        page = ac.list_hosted_configuration_versions(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            MaxResults=2,
            **({"NextToken": token} if token else {}),
        )
        items = page.get("Items", [])
        assert len(items) <= 2, f"MaxResults=2 violated on page {pages}: {len(items)} items"
        seen.extend(v["VersionNumber"] for v in items)
        token = page.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError(f"pagination did not terminate within {MAX_PAGES} pages")

    assert pages == 3, f"5 versions at MaxResults=2 must take exactly 3 pages, took {pages}"
    assert sorted(seen) == [1, 2, 3, 4, 5], (
        f"paging must enumerate every version exactly once; got {seen}"
    )
    assert set(page_one) <= set(seen), f"page 1 {page_one} must be part of the paged listing {seen}"
    assert token is None, (
        f"the final page must NOT carry a NextToken; got {token!r} — a token on the last page "
        f"makes every generic paginator loop forever"
    )

    # --- Summaries carry the metadata but not the body.
    unpaged = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=cp_id
    )["Items"]
    assert sorted(v["VersionNumber"] for v in unpaged) == [1, 2, 3, 4, 5], unpaged
    for summary in unpaged:
        assert summary["ApplicationId"] == app_id, summary
        assert summary["ConfigurationProfileId"] == cp_id, summary
        assert summary["ContentType"] == "application/json", summary
        assert "Content" not in summary, (
            f"a list summary must not embed the configuration body; got keys {sorted(summary)}"
        )
    labels = {v["VersionNumber"]: v.get("VersionLabel") for v in unpaged}
    assert labels[labelled_version] == label, (
        f"version {labelled_version} must report VersionLabel={label!r}, got "
        f"{labels[labelled_version]!r}"
    )
    unlabelled = {n: lbl for n, lbl in labels.items() if n != labelled_version}
    assert all(lbl is None for lbl in unlabelled.values()), (
        f"versions created without a label must report no VersionLabel; got {unlabelled} — "
        f"note the sibling get-latest-configuration check records that at least one emulator "
        f"substitutes the version NUMBER as the label"
    )

    # --- The VersionLabel filter selects exactly one version, not everything.
    filtered = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionLabel=label
    )["Items"]
    assert [v["VersionNumber"] for v in filtered] == [labelled_version], (
        f"VersionLabel={label!r} must select exactly version {labelled_version}; got "
        f"{[v['VersionNumber'] for v in filtered]} — an emulator that ignores the filter "
        f"returns all five"
    )
    assert filtered[0]["VersionLabel"] == label, filtered[0]

    # --- A label nobody used selects nothing, and does not fall back to "everything".
    empty = ac.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionLabel="no-such-label-here"
    )
    assert empty.get("Items", []) == [], (
        f"an unmatched VersionLabel filter must return an empty list, not a fallback; got "
        f"{empty.get('Items')!r}"
    )
    assert not empty.get("NextToken"), empty.get("NextToken")

    # --- The listing is scoped to the profile: a foreign profile id is a 404, not an
    # unfiltered listing.
    code, code_msg = _error(
        lambda: ac.list_hosted_configuration_versions(
            ApplicationId=app_id, ConfigurationProfileId="zzzzzzz"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"listing versions of a nonexistent configuration profile must be "
        f"ResourceNotFoundException, got {code!r}"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert code_msg == (
        f"Configuration Profile with Application Id {app_id} and Configuration Profile Id zzzzzzz "
        f"could not be found for account {account}."
    ), f"unexpected message: {code_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
