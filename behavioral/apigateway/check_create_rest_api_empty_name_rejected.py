"""create-rest-api-empty-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rest-api-empty-name-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRestApi with an empty required name string is rejected, never creates a nameless API."""
    apigw = ctx.client("apigateway")

    code, message = _error(lambda: apigw.create_rest_api(name=""))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = "Name cannot be an empty string"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect-absent: no REST API with an empty name exists anywhere in the account.
    apis = _list_all_rest_apis(apigw)
    assert not any(api.get("name") == "" for api in apis), "a nameless API was created"

    # positive control: the same call with a valid non-empty name succeeds.
    good_name = ctx.unique_name("sim2real-behav-restapi-")
    created = apigw.create_rest_api(name=good_name, tags={"sim2real": "create-rest-api-empty-name-rejected"})
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=created["id"]))
    assert created["name"] == good_name

    fetched = apigw.get_rest_api(restApiId=created["id"])
    assert fetched["name"] == good_name


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _list_all_rest_apis(apigw):
    items = []
    resp = apigw.get_rest_apis(limit=500)
    items.extend(resp.get("items", []))
    while resp.get("position"):
        resp = apigw.get_rest_apis(limit=500, position=resp["position"])
        items.extend(resp.get("items", []))
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
