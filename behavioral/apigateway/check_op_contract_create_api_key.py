"""op-contract-create-api-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-api-key"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiKey returns a generated value/enabled flag on success; a stageKeys entry
    referencing a nonexistent restApi/stage yields NotFoundException and creates no key,
    while the identical stageKeys shape succeeds once it names a real, deployed stage."""
    apigw = ctx.client("apigateway")

    name = ctx.unique_name("sim2real-apigw-key-")
    resp = apigw.create_api_key(
        name=name, description="behavioral check", enabled=True, tags={"sim2real": "true"}
    )
    key_id = resp["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_api_key(apiKey=key_id)))

    assert resp["enabled"] is True, f"expected enabled=True, got {resp.get('enabled')!r}"
    assert resp["name"] == name, f"expected name {name!r}, got {resp.get('name')!r}"
    assert isinstance(resp["value"], str) and len(resp["value"]) >= 20, (
        f"expected a generated value of at least 20 chars, got {resp.get('value')!r}"
    )
    fetched = apigw.get_api_key(apiKey=key_id, includeValue=True)
    assert fetched["value"] == resp["value"], (
        f"GetApiKey value {fetched.get('value')!r} != CreateApiKey value {resp['value']!r}"
    )
    assert fetched["enabled"] is True, f"expected enabled=True, got {fetched.get('enabled')!r}"

    # error boundary: stageKeys referencing a restApi/stage that does not exist -> NotFoundException,
    # and no ApiKey is created as a side effect of the failed call.
    bad_name = ctx.unique_name("sim2real-apigw-key-bad-")
    err = _client_error(
        lambda: apigw.create_api_key(
            name=bad_name,
            enabled=True,
            stageKeys=[{"restApiId": "nonexist1234", "stageName": "prod"}],
        )
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == f"Invalid API identifier specified {ctx.account}:nonexist1234", (
        f"expected the exact NotFound message, got {err.get('Message')!r}"
    )
    listed = apigw.get_api_keys(nameQuery=bad_name)["items"]
    assert listed == [], "no ApiKey should exist for the failed CreateApiKey call"

    # positive control: the identical stageKeys shape succeeds once it references a real,
    # deployed stage -- without this, a target that rejects every stageKeys entry
    # (valid or not) would pass the error boundary above for the wrong reason.
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"), tags={"sim2real": "true"}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(
        r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/"
    )
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = ctx.unique_name("s")
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)

    good_name = ctx.unique_name("sim2real-apigw-key-good-")
    good = apigw.create_api_key(
        name=good_name,
        enabled=True,
        stageKeys=[{"restApiId": api_id, "stageName": stage_name}],
        tags={"sim2real": "true"},
    )
    good_id = good["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_api_key(apiKey=good_id)))
    assert good["name"] == good_name, f"expected name {good_name!r}, got {good.get('name')!r}"
    listed_good = apigw.get_api_keys(nameQuery=good_name)["items"]
    assert any(k["id"] == good_id for k in listed_good), (
        "the api key created with a valid stageKeys reference must be visible via GetApiKeys"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
