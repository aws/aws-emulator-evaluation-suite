"""api-key-default-expiry-seven-days."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "api-key-default-expiry-seven-days"
GROUP = "state"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKey without `expires` defaults to ~7 days out (hour-rounded), with `deletes` 60 days
    after that; ListApiKeys reports the same values.
    """
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]

    before = time.time()
    key = appsync.create_api_key(apiId=api_id)["apiKey"]
    key_id = key["id"]
    ctx.on_cleanup(lambda: _best_effort_delete_key(appsync, api_id, key_id))
    after = time.time()

    expected = before + 7 * 86400
    tolerance = 3700  # AppSync rounds expiry down to the nearest hour
    assert abs(key["expires"] - expected) <= tolerance, (
        f"expires={key['expires']} not within {tolerance}s of expected {expected}"
    )
    assert key["expires"] <= after + 7 * 86400 + tolerance, (
        f"expires={key['expires']} exceeds upper bound {after + 7 * 86400 + tolerance}"
    )
    # `deletes` is NOT the same instant as `expires`: AppSync retains an expired API key for a
    # further 60-day grace period before actually deleting it, so `deletes` == `expires` + 60
    # days (also rounded to the hour), not `deletes` == `expires`.
    grace_period = 60 * 86400
    assert abs(key["deletes"] - (key["expires"] + grace_period)) <= tolerance, (
        f"deletes={key['deletes']} not within {tolerance}s of expires+60d="
        f"{key['expires'] + grace_period}"
    )

    listed = appsync.list_api_keys(apiId=api_id)["apiKeys"]
    matches = [k for k in listed if k["id"] == key_id]
    assert len(matches) == 1, f"expected exactly one matching api key, found {len(matches)}"
    assert matches[0]["expires"] == key["expires"], (
        f"ListApiKeys expires drifted: {matches[0]['expires']} != {key['expires']}"
    )
    assert matches[0]["deletes"] == key["deletes"], (
        f"ListApiKeys deletes drifted: {matches[0]['deletes']} != {key['deletes']}"
    )


def _best_effort_delete_key(appsync, api_id, key_id):
    try:
        appsync.delete_api_key(apiId=api_id, id=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"), authenticationType=auth_type
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
