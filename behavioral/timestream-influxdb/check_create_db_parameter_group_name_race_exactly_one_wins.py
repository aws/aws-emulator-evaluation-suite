"""create-db-parameter-group-name-race-exactly-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-db-parameter-group-name-race-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["timestream-influxdb"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateDbParameterGroup calls with one name yield at least one success, and the groups listed under
    that name are exactly the reported successes, each readable by GetDbParameterGroup."""
    influx = ctx.client("timestream-influxdb")
    name = ctx.unique_name("sim2real-pgrace-")
    racer_count = 8

    def attempt(_i):
        from botocore.exceptions import ClientError

        try:
            resp = influx.create_db_parameter_group(name=name, description="race")
            return ("success", resp["id"])
        except ClientError as err:
            return (err.response["Error"]["Code"], None)

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(attempt, range(racer_count)))

    outcomes = [r[0] for r in results]
    successes = [r for r in results if r[0] == "success"]
    rejections = [r for r in results if r[0] != "success"]

    assert len(successes) >= 1, f"expected at least one racer to succeed, got outcomes={outcomes!r}"

    success_ids = {r[1] for r in successes}
    assert len(success_ids) == len(successes), f"success ids must be distinct: {successes!r}"

    matches = [g for g in _list_all_parameter_groups(influx) if g["name"] == name]
    matched_ids = {g["id"] for g in matches}
    assert matched_ids == success_ids, (
        f"persisted groups with name={name!r} must exactly match reported successes: "
        f"persisted={matched_ids!r} reported={success_ids!r} rejections={[r[0] for r in rejections]!r}"
    )

    for winner_id in success_ids:
        fetched = influx.get_db_parameter_group(identifier=winner_id)
        assert fetched["name"] == name, f"expected name={name!r}, got {fetched['name']!r}"
        assert fetched["id"] == winner_id, f"expected id={winner_id!r}, got {fetched['id']!r}"

    # Note: Timestream for InfluxDB has no DeleteDbParameterGroup API, so the winning
    # group(s) are intentionally left in the account (no cleanup call is possible);
    # ctx.unique_name keeps them from colliding with other runs.


def _list_all_parameter_groups(influx):
    items = []
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = influx.list_db_parameter_groups(**kwargs)
        items.extend(resp.get("items", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
