"""concurrent-extension-version-optimistic-lock."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-extension-version-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateExtension calls that both pin LatestVersionNumber=1 on the
    same extension race to create version 2: exactly one succeeds, the other is
    rejected with ConflictException, and the extension ends at version 2 (not 3)."""
    appconfig = ctx.client("appconfig")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    name = ctx.unique_name("sim2real-behav-ext-")
    actions = {"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": topic_arn}]}
    created = appconfig.create_extension(Name=name, Actions=actions)
    ext_id = created["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))
    assert created["VersionNumber"] == 1, f"expected initial extension at version 1, got {created['VersionNumber']}"

    def race(i: int) -> tuple[str, Any]:
        try:
            resp = appconfig.create_extension(
                Name=name,
                Actions=actions,
                Description=f"racer-{i}",
                # A compare-and-swap: ConflictException if another writer already advanced it.
                LatestVersionNumber=1,
            )
            return ("ok", resp["VersionNumber"])
        except Exception as exc:  # noqa: BLE001
            return ("err", _error_code_from_exc(exc), _error_message_from_exc(exc))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race, range(2)))

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, f"expected exactly one winner, got {results}"
    assert len(errs) == 1, f"expected exactly one loser, got {results}"
    _, loser_code, loser_message = errs[0]
    assert loser_code == "ConflictException", f"loser got wrong error: {results}"
    # Which conflict the loser sees depends on how far the winner got; each is AWS's exact wording.
    stale = "LatestVersionNumber supplied in request 1 does not match latest version 2."
    exists = f"Extension with id {ext_id} and versionNumber 2 already exists for account {ctx.account}."
    expected = stale if loser_message.startswith("LatestVersionNumber ") else exists
    assert loser_message == expected, f"loser got wrong message: {results}"
    assert oks[0][1] == 2, f"winner should land on version 2, got {results}"

    latest = appconfig.get_extension(ExtensionIdentifier=ext_id)
    # exactly one new version was created by the race, not two
    assert latest["VersionNumber"] == 2, f"expected exactly one new version from the race, got {latest['VersionNumber']}"


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def _error_message_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Message")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
