"""concurrent-update-extension-version-last-writer-wins."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "concurrent-update-extension-version-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-concurrent-update-extension-version-last-writer-wins"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateExtension calls at VersionNumber=1 all succeed without forking a version:
    the extension ends with exactly one racer's Description and stays updatable afterward."""
    from concurrent.futures import ThreadPoolExecutor

    from botocore.exceptions import ClientError

    appconfig = ctx.client("appconfig")
    action_uri = f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-notify"
    ext = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": action_uri}]},
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    assert ext["VersionNumber"] == 1, f"expected a freshly created extension to start at VersionNumber 1, got {ext['VersionNumber']}"
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id)))

    def _racer(i):
        try:
            resp = appconfig.update_extension(
                ExtensionIdentifier=ext_id, VersionNumber=1, Description=f"racer-{i}",
            )
            return ("ok", resp["VersionNumber"], resp.get("Description"))
        except ClientError as e:
            return (e.response["Error"]["Code"], None, None)

    n = 6
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_racer, range(n)))

    successes = [r for r in results if r[0] == "ok"]
    assert len(successes) == n, f"expected all racers to succeed (UpdateExtension is not version-locked), got {results}"
    assert all(version == 1 for _, version, _ in successes), (
        f"UpdateExtension must not create/bump an extension version, got {results}"
    )

    final = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert final["VersionNumber"] == 1, "concurrent in-place updates must not create additional extension versions"
    expected_descriptions = {f"racer-{i}" for i in range(n)}
    assert final["Description"] in expected_descriptions, (
        f"extension state corrupted by concurrent writers: {final['Description']!r}"
    )

    # State is not corrupted: a subsequent serial update still lands cleanly.
    after = appconfig.update_extension(
        ExtensionIdentifier=ext_id, VersionNumber=1, Description="after-concurrent-writers")
    assert after["Description"] == "after-concurrent-writers", (
        f"serial update after the race must land cleanly, got {after['Description']!r}"
    )
    assert after["VersionNumber"] == 1, f"serial update must not bump the version, got {after['VersionNumber']}"
    confirm = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert confirm["Description"] == "after-concurrent-writers", (
        f"independent read must reflect the serial update, got {confirm['Description']!r}"
    )



def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
