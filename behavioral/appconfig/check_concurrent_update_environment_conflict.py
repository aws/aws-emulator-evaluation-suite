"""concurrent-update-environment-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-environment-conflict"
GROUP = "concurrency"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-concurrent-update-environment"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateEnvironment calls resolve deterministically (last-writer-wins) without
    corrupting environment state -- the environment ends up with exactly one of the two written
    Description values, never a blend/corruption, and remains fully updatable afterward.
    """
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    env_id = appconfig.create_environment(
        ApplicationId=app_id, Name="env-race", Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_environment(appconfig, app_id, env_id))

    desc_a = "concurrent-writer-A"
    desc_b = "concurrent-writer-B"

    def writer(desc):
        return appconfig.update_environment(
            ApplicationId=app_id, EnvironmentId=env_id, Description=desc
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(writer, desc_a)
        fut_b = pool.submit(writer, desc_b)
        result_a = fut_a.result()
        result_b = fut_b.result()

    # Both racers succeed (no ConflictException on UpdateEnvironment); each response reflects
    # exactly its own write, never a mix of the two.
    assert result_a["Description"] == desc_a, (
        f"expected racer A's own response to echo {desc_a!r}, got {result_a['Description']!r}"
    )
    assert result_b["Description"] == desc_b, (
        f"expected racer B's own response to echo {desc_b!r}, got {result_b['Description']!r}"
    )

    final = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert final["Description"] in (desc_a, desc_b), (
        f"environment state corrupted by concurrent writers: {final['Description']!r}"
    )

    # State is not corrupted: a subsequent serial update still lands cleanly.
    after = appconfig.update_environment(
        ApplicationId=app_id, EnvironmentId=env_id, Description="after-concurrent-writers"
    )
    assert after["Description"] == "after-concurrent-writers", (
        f"expected serial post-race update to land cleanly, got {after['Description']!r}"
    )
    confirm = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert confirm["Description"] == "after-concurrent-writers", (
        f"expected independent read to reflect the serial update, got {confirm['Description']!r}"
    )


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_environment(appconfig, app_id, env_id):
    try:
        appconfig.delete_environment(ApplicationId=app_id, EnvironmentId=env_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
