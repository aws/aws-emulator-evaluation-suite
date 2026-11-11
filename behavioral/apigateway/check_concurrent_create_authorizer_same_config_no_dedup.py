"""concurrent-create-authorizer-same-config-no-dedup."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-authorizer-same-config-no-dedup"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateAuthorizer calls with identical config (distinct names) both
    succeed as distinct resources, with no unintended dedup/lock collision."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")

    api_name = ctx.unique_name("sim2real-api-")
    api = apigw.create_rest_api(name=api_name, tags={"sim2real": "concurrent-create-authorizer-same-config-no-dedup"})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    account_id = sts.get_caller_identity()["Account"]
    shared_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:{account_id}:function:sim2real-fake-authorizer/invocations"
    )

    name_a = ctx.unique_name("sim2real-authz-a-")
    name_b = ctx.unique_name("sim2real-authz-b-")

    def _create(name: str) -> dict:
        return apigw.create_authorizer(
            restApiId=api_id,
            name=name,
            type="TOKEN",
            authorizerUri=shared_uri,
            identitySource="method.request.header.Authorization",
            authorizerResultTtlInSeconds=300,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_create, name_a)
        fut_b = pool.submit(_create, name_b)
        result_a = fut_a.result()
        result_b = fut_b.result()

    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=result_a["id"]))
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=result_b["id"]))

    assert result_a["id"] != result_b["id"], "concurrent creates were deduplicated into a single authorizer"

    listed = apigw.get_authorizers(restApiId=api_id)["items"]
    listed_by_id = {a["id"]: a for a in listed}

    assert result_a["id"] in listed_by_id, "authorizer A missing from GetAuthorizers"
    assert result_b["id"] in listed_by_id, "authorizer B missing from GetAuthorizers"

    for name, authz in ((name_a, listed_by_id[result_a["id"]]), (name_b, listed_by_id[result_b["id"]])):
        assert authz["name"] == name, f"expected name {name!r}, got {authz['name']!r}"
        assert authz["authorizerUri"] == shared_uri, (
            f"expected authorizerUri {shared_uri!r}, got {authz['authorizerUri']!r}"
        )
        assert authz["type"] == "TOKEN", f"expected type TOKEN, got {authz['type']!r}"
        assert authz["identitySource"] == "method.request.header.Authorization", (
            f"expected identitySource method.request.header.Authorization, got {authz['identitySource']!r}"
        )
        assert authz["authorizerResultTtlInSeconds"] == 300, (
            f"expected authorizerResultTtlInSeconds 300, got {authz['authorizerResultTtlInSeconds']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
