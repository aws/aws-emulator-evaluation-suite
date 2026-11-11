"""application-config-unicode-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "application-config-unicode-round-trip"
GROUP = "data-plane"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode and special-character appConfigs values come back unchanged from GetApplication after
    CreateApplication and after UpdateApplication."""
    client = ctx.client("opensearch")
    name = _app_name(ctx)
    value_v1 = "héllo-世界-\u00e9\u00e8\u4e2d\u6587-café-Zürich-①②③"
    created = client.create_application(
        name=name,
        appConfigs=[
            {"key": "opensearchDashboards.dashboardAdmin.users", "value": value_v1},
        ],
        tagList=[{"Key": "sim2real", "Value": "true"}],
    )
    app_id = created["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    _wait_application_status(ctx, app_id, {"ACTIVE"}, {"FAILED"})

    got = client.get_application(id=app_id)
    configs = {c["key"]: c["value"] for c in got.get("appConfigs", [])}
    assert configs.get("opensearchDashboards.dashboardAdmin.users") == value_v1, (
        f"unicode appConfig value did not round-trip on create: {configs!r}"
    )

    value_v2 = "日本語-emoji-🚀-Ñoño-Москва-ç漢字"
    client.update_application(
        id=app_id,
        appConfigs=[
            {"key": "opensearchDashboards.dashboardAdmin.users", "value": value_v2},
        ],
    )
    _wait_application_status(ctx, app_id, {"ACTIVE"}, {"FAILED"})

    got2 = client.get_application(id=app_id)
    configs2 = {c["key"]: c["value"] for c in got2.get("appConfigs", [])}
    assert configs2.get("opensearchDashboards.dashboardAdmin.users") == value_v2, (
        f"unicode appConfig value did not round-trip on update: {configs2!r}"
    )
    assert configs2.get("opensearchDashboards.dashboardAdmin.users") != value_v1, (
        f"update did not replace the prior unicode value, still {value_v1!r}"
    )


def _app_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-app-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:30]


def _wait_application_status(ctx, app_id, ok_statuses, terminal_bad_statuses, timeout_s=600.0):
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        got = client.get_application(id=app_id)
        last = got.get("status")
        if last in ok_statuses:
            return got
        if last in terminal_bad_statuses:
            raise AssertionError(f"application {app_id} reached bad status {last!r}: {got!r}")
        time.sleep(5)
    raise AssertionError(f"application {app_id} did not reach {ok_statuses} within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
