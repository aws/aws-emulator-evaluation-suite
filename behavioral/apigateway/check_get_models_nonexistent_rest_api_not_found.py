"""get-models-nonexistent-rest-api-not-found."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-models-nonexistent-rest-api-not-found"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _model_name(prefix: str) -> str:
    """Lowercase alphanumeric model name (apigateway model names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return prefix + "".join(random.choice(alphabet) for _ in range(10))


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
    """GetModels lists the models created on the API, alongside its built-in defaults; a
    restApiId that does not exist is refused with NotFoundException rather than an empty page."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))

    names = {_model_name("sim2realmodela"), _model_name("sim2realmodelb")}
    created_ids = set()
    for name in names:
        created = apigw.create_model(
            restApiId=api_id,
            name=name,
            contentType="application/json",
            schema='{"$schema": "http://json-schema.org/draft-04/schema#", "type": "object"}',
        )
        created_ids.add(created["id"])

    listing = apigw.get_models(restApiId=api_id)["items"]
    listed_ids = {m["id"] for m in listing}
    listed_names = {m["name"] for m in listing}
    assert created_ids <= listed_ids, f"expected ids {created_ids} to be listed, got {listed_ids}"
    assert names <= listed_names, f"expected names {names} to be listed, got {listed_names}"

    code, message = _error(lambda: apigw.get_models(restApiId="sim2real-missing-rest-api"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}: {message!r}"
    assert message == (
        f"Invalid API identifier specified {ctx.account}:sim2real-missing-rest-api"
    ), f"unexpected NotFoundException message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
