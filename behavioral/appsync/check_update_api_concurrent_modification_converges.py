"""update-api-concurrent-modification-converges."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "update-api-concurrent-modification-converges"
GROUP = "concurrency"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateApi calls on the same Api converge to one final name; any
    losers must fail with ConcurrentModificationException specifically, never
    a different/unexpected error."""
    appsync = ctx.client("appsync")
    base_name = ctx.unique_name("sim2real-behav-")
    event_config = _event_config()

    api = appsync.create_api(name=base_name, eventConfig=event_config, tags={"sim2real": CHECK})["api"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))

    racer_count = 6
    candidate_names = [f"{base_name}-r{i}" for i in range(racer_count)]

    def _update(new_name: str):
        try:
            appsync.update_api(apiId=api_id, name=new_name, eventConfig=event_config)
            return ("ok", new_name, None)
        except Exception as err:  # noqa: BLE001 - classify below
            return ("error", new_name, _code_of(err))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_update, nm) for nm in candidate_names]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]
    bad_error_codes = sorted({code for (_, _, code) in errors if code != "ConcurrentModificationException"})

    assert len(successes) >= 1, f"expected at least one racing UpdateApi to succeed, got {results}"
    assert not bad_error_codes, (
        f"racing UpdateApi calls raised non-ConcurrentModificationException errors: {bad_error_codes}"
    )

    # The Api must settle on exactly one of the attempted names -- not a mix,
    # not the original, and not something corrupted by the race.
    final = appsync.get_api(apiId=api_id)["api"]
    assert final["name"] in candidate_names, (
        f"final Api name {final['name']!r} is not one of the racing candidates {candidate_names}"
    )


def _event_config() -> dict:
    return {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }


def _code_of(err) -> str:
    from botocore.exceptions import ClientError

    if isinstance(err, ClientError):
        return err.response["Error"]["Code"]
    return type(err).__name__


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
