"""concurrent-update-extension-optimistic-lock."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-update-extension-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-concurrent-update-extension-optimistic-lock"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtension has no optimistic lock on VersionNumber: concurrent callers supplying the current VersionNumber
    all succeed, VersionNumber is never bumped, and the extension ends with exactly one racer's Description
    (last writer wins, never a blend); a later serial update with the same VersionNumber also succeeds."""
    appconfig = ctx.client("appconfig")
    action_uri = f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-notify"
    ext = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "noop", "Description": "test action", "Uri": action_uri}]},
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    assert ext["VersionNumber"] == 1, f"expected a freshly created extension to start at VersionNumber 1, got {ext['VersionNumber']}"

    def _cleanup():
        for version in (3, 2, 1):
            try:
                appconfig.delete_extension(ExtensionIdentifier=ext_id, VersionNumber=version)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    racers = 2
    results = []

    def _racer(i):
        try:
            resp = appconfig.update_extension(
                ExtensionIdentifier=ext_id,
                VersionNumber=1,
                Description=f"racer-{i}",
            )
            return ("ok", resp)
        except Exception as err:
            return ("err", _error_code_from(err))

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_racer, i) for i in range(racers)]
        for fut in as_completed(futures):
            results.append(fut.result())

    oks = [payload for kind, payload in results if kind == "ok"]
    errs = [payload for kind, payload in results if kind == "err"]
    assert len(oks) == racers, f"expected all {racers} racers to succeed (no optimistic lock), got {results}"
    assert len(errs) == 0, f"expected no ConflictException/errors among racers, got {errs}"
    assert all(ok["VersionNumber"] == 1 for ok in oks), (
        f"UpdateExtension must not bump VersionNumber, got {[ok['VersionNumber'] for ok in oks]}"
    )

    final = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert final["VersionNumber"] == 1, f"concurrent in-place updates must not create a new version, got {final['VersionNumber']}"
    expected_descriptions = {f"racer-{i}" for i in range(racers)}
    assert final["Description"] in expected_descriptions, (
        f"extension state corrupted by concurrent writers: {final['Description']!r}"
    )
    assert final["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "noop", (
        f"Actions must be untouched by the racing Description-only updates, got {final['Actions']}"
    )

    # A further serial update reusing the same (never-changing) VersionNumber=1
    # succeeds cleanly too -- confirms there is no lock to trip and state is not
    # corrupted by the earlier concurrent writers.
    third = appconfig.update_extension(
        ExtensionIdentifier=ext_id, VersionNumber=1, Description="third-update"
    )
    assert third["VersionNumber"] == 1, f"serial update must not bump the version, got {third['VersionNumber']}"
    confirm = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert confirm["Description"] == "third-update", (
        f"independent read must reflect the serial update, got {confirm['Description']!r}"
    )



def _error_code_from(err):
    from botocore.exceptions import ClientError

    if isinstance(err, ClientError):
        return err.response["Error"]["Code"]
    return None


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
