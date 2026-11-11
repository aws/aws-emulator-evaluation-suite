"""concurrent-create-configuration-set-denied-consistently."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-configuration-set-denied-consistently"
GROUP = "concurrency"
SERVICES = ["pinpoint-sms-voice"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateConfigurationSet calls for one name are all refused with HTTP 403
    AccessDeniedException "Access Denied", none wins, and ListConfigurationSets does not show the
    name."""
    client = ctx.client("pinpoint-sms-voice")
    name = ctx.unique_name("sim2real-behav-race-cfgset-")

    def attempt(_i):
        try:
            client.create_configuration_set(ConfigurationSetName=name)
            return {"ok": True}
        except ClientError as e:
            return {
                "ok": False,
                "code": e.response["Error"]["Code"],
                "message": e.response["Error"].get("Message"),
                "status": e.response["ResponseMetadata"]["HTTPStatusCode"],
            }

    n_racers = 8
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(attempt, range(n_racers)))

    # guaranteed teardown even if a racer unexpectedly wins the race -- delete is
    # best-effort on cleanup, so this is a no-op in the (expected) all-denied case.
    ctx.on_cleanup(lambda _n=name: _delete_configuration_set(client, _n))

    winners = [r for r in results if r["ok"]]
    assert not winners, f"expected every racer denied, got {len(winners)} winner(s) among {results}"

    codes = {r["code"] for r in results}
    assert codes == {"AccessDeniedException"}, f"expected uniform denial, got {results}"

    for r in results:
        assert r["message"] == "Access Denied", f"expected the Message 'Access Denied', got {r}"
        assert r["status"] == 403, f"expected HTTP 403 for AccessDeniedException, got {r}"

    # effect absent: nothing was created, so the name never surfaces in ListConfigurationSets
    names: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = client.list_configuration_sets(**kwargs)
        names.extend(page.get("ConfigurationSets", []))
        token = page.get("NextToken")
        if not token:
            break
    assert name not in names, f"{name} must not appear after a fully-denied create race"


def _delete_configuration_set(client, name):
    """Teardown: delete the set; the "Access Denied" refusal is the same answer that refused every
    create, so nothing exists to delete."""
    try:
        client.delete_configuration_set(ConfigurationSetName=name)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "NotFoundException":
            return
        if err["Code"] != "AccessDeniedException" or err.get("Message") != "Access Denied":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
