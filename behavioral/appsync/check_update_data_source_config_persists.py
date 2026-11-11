"""update-data-source-config-persists."""
from __future__ import annotations

import re

from behavioral_harness import tags

def _sanitize(name):
    """AppSync data source/function names must match ^[_A-Za-z][_0-9A-Za-z]*$."""
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", name)
    if not cleaned or not re.match(r"[_A-Za-z]", cleaned[0]):
        cleaned = "n_" + cleaned
    return cleaned

CHECK = "update-data-source-config-persists"
GROUP = 'data-source'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataSource with a new httpConfig.endpoint is reflected on GetDataSource."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real-owner": "behavioral-check"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    name = _sanitize(ctx.unique_name("sim2real-behav-httpds_"))

    # HTTP needs no service role, unlike DynamoDB. AppSync resolves the endpoint's DNS at create
    # time and rejects unknown hosts with BadRequestException, so the endpoints are real hosts.
    svc.create_data_source(
        apiId=api_id,
        name=name,
        type="HTTP",
        httpConfig={"endpoint": "https://sts.us-west-2.amazonaws.com"},
    )
    got = svc.get_data_source(apiId=api_id, name=name)["dataSource"]
    assert got["type"] == "HTTP", got
    assert got["httpConfig"]["endpoint"] == "https://sts.us-west-2.amazonaws.com", got["httpConfig"]

    svc.update_data_source(
        apiId=api_id,
        name=name,
        type="HTTP",
        httpConfig={"endpoint": "https://sts.us-east-1.amazonaws.com"},
    )
    got2 = svc.get_data_source(apiId=api_id, name=name)["dataSource"]
    assert got2["httpConfig"]["endpoint"] == "https://sts.us-east-1.amazonaws.com", got2["httpConfig"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
