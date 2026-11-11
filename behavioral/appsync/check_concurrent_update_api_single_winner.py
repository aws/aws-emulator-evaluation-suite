"""concurrent-update-api-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-api-single-winner"
GROUP = "concurrency"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateApi calls against the same Api resolve deterministically (one
    wins / one gets ConcurrentModificationException), leaving a single consistent final
    state."""
    appsync = ctx.client("appsync")
    api = appsync.create_api(
        name=ctx.unique_name("sim2real-behav-"),
        eventConfig=_event_config(),
        tags={"sim2real": "concurrent-update-api-single-winner"},
    )["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))

    name_a = ctx.unique_name("sim2real-behav-race-a-")
    name_b = ctx.unique_name("sim2real-behav-race-b-")

    def _update(name):
        try:
            appsync.update_api(apiId=api_id, name=name, eventConfig=_event_config())
            return ("ok", name)
        except ClientError as exc:
            return (exc.response["Error"]["Code"], name, exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            f.result()
            for f in [pool.submit(_update, name_a), pool.submit(_update, name_b)]
        ]

    oks = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] != "ok"]
    assert len(oks) >= 1, f"expected at least one racer to win, got {results}"
    for code, name, message in errors:
        assert code == "ConcurrentModificationException", (
            f"unexpected loser error {code!r} for update({name!r})"
        )
        expected = "API is currently being updated, please wait and try again."
        assert message == expected, f"expected loser message {expected!r}, got {message!r}"

    final = appsync.get_api(apiId=api_id)["api"]
    assert final["name"] in {name_a, name_b}, (
        f"final name {final['name']!r} does not match either racer; state may be corrupted"
    )


def _event_config() -> dict:
    return {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
