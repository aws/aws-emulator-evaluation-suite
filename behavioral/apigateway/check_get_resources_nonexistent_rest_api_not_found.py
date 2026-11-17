"""get-resources-nonexistent-rest-api-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resources-nonexistent-rest-api-not-found"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _error(fn):
    """Call fn(); return the ClientError's (Error.Code, Error.Message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_rest_api(apigw, api_id, *, budget_s=150.0):
    """DeleteRestApi, retrying TooManyRequestsException (one call per ~30s per account) to
    budget_s; NotFoundException means it is already gone, anything else raises."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise RuntimeError(f"rest api {api_id} not deleted: {code}") from exc
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResources lists the root plus any resource created on the API; a restApiId that
    does not exist is refused with NotFoundException rather than an empty page."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))

    root_items = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(i["id"] for i in root_items if i["path"] == "/")
    part = "sim2real-child"
    child_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=part)["id"]

    listing = apigw.get_resources(restApiId=api_id)["items"]
    listed_ids = {r["id"] for r in listing}
    assert {root_id, child_id} <= listed_ids, (
        f"expected root {root_id!r} and child {child_id!r} to be listed, got {listed_ids!r}"
    )
    listed_child = next(r for r in listing if r["id"] == child_id)
    assert listed_child["pathPart"] == part, f"expected pathPart {part!r}, got {listed_child['pathPart']!r}"

    code, message = _error(lambda: apigw.get_resources(restApiId="sim2real-missing-rest-api"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}: {message!r}"
    assert message == (
        f"Invalid API identifier specified {ctx.account}:sim2real-missing-rest-api"
    ), f"unexpected NotFoundException message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
