"""create-rest-api-with-an-empty-description-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rest-api-with-an-empty-description-rejected"
GROUP = "validation"
SERVICES = ["apigateway"]

_PAGE_CAP = 200  # a walk whose token never ends fails instead of spinning


def _wait_cap(ctx, cap_s: float) -> float:
    """cap_s, shortened when the runner stops the check sooner, keeping 5 s for the failure."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _paced(ctx, call):
    """call(), repeated while API Gateway answers TooManyRequestsException for the account."""
    deadline = time.monotonic() + _wait_cap(ctx, 120.0)
    for attempt in range(10):
        try:
            return call()
        except ClientError as exc:
            last = attempt == 9 or time.monotonic() >= deadline
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or last:
                raise
        time.sleep(min(2 ** attempt, 30))


def _drop_api(apigw, api_id: str):
    """A cleanup deleting the REST API through DeleteRestApi's per-account pacing; a failure raises."""

    def undo() -> None:
        deadline = time.monotonic() + 100.0
        for attempt in range(8):
            try:
                apigw.delete_rest_api(restApiId=api_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NotFoundException":
                    return
                if code != "TooManyRequestsException" or attempt == 7 or time.monotonic() >= deadline:
                    raise
            time.sleep(min(5 * 2 ** attempt, 30, max(1.0, deadline - time.monotonic())))

    return undo


def _new_api(ctx, apigw, **params) -> str:
    """CreateRestApi with params, its delete registered at once; returns the API id."""
    api_id = _paced(ctx, lambda: apigw.create_rest_api(**params))["id"]
    ctx.on_cleanup(_drop_api(apigw, api_id))
    return api_id


def _listed(ctx, apigw, match):
    """Every GetRestApis item match(item) accepts, across all pages."""
    found, kwargs = [], {"limit": 500}
    for _ in range(_PAGE_CAP):
        page = _paced(ctx, lambda: apigw.get_rest_apis(**kwargs))
        found += [item for item in page.get("items", []) if match(item)]
        if not page.get("position"):
            return found
        kwargs["position"] = page["position"]
    raise AssertionError(f"GetRestApis still returned a position after {_PAGE_CAP} pages")


def _refusal(fn, code: str):
    """Call fn, which AWS must refuse with code; return the ClientError.

    A success fails the check, and a different code fails it raised from AWS's own error.
    """
    try:
        result = fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == code:
            return exc
        raise AssertionError(f"expected {code}, got {exc.response['Error']['Code']}") from exc
    raise AssertionError(f"expected {code}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRestApi with an empty description is refused and creates no API; the same create with
    a one-character description succeeds and reads it back.
    """
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-aged-")

    def refused():
        api = apigw.create_rest_api(name=name, description="", tags={"sim2real": CHECK})
        ctx.on_cleanup(_drop_api(apigw, api["id"]))
        return api

    err = _refusal(lambda: _paced(ctx, refused), "BadRequestException")
    message = err.response["Error"]["Message"]
    assert message == "Description cannot be an empty string", f"the refusal carried the message {message!r}"

    same_name = _listed(ctx, apigw, lambda item: item["name"] == name)
    assert same_name == [], f"the refused create left {len(same_name)} REST API(s) under its name"

    api_id = _new_api(ctx, apigw, name=name, description="x", tags={"sim2real": CHECK})
    got = _paced(ctx, lambda: apigw.get_rest_api(restApiId=api_id)).get("description")
    assert got == "x", f"the accepted create reads description={got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
