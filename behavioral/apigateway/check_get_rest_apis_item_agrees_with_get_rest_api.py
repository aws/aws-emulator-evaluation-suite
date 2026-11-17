"""get-rest-apis-item-agrees-with-get-rest-api."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-rest-apis-item-agrees-with-get-rest-api"
GROUP = "representation"
SERVICES = ["apigateway"]

_PAGE_CAP = 200  # a walk whose token never ends fails instead of spinning

# RestApi members both views name. GetRestApis items carry no tags, so tags are not compared.
_SHARED = (
    "apiKeySource", "apiStatus", "apiStatusMessage", "binaryMediaTypes", "createdDate", "description",
    "disableExecuteApiEndpoint", "endpointAccessMode", "endpointConfiguration", "id",
    "minimumCompressionSize", "name", "policy", "rootResourceId", "securityPolicy", "version", "warnings",
)


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The GetRestApis item for a REST API equals GetRestApi on every field both return, so the
    listing reports the same configuration as the read.
    """
    apigw = ctx.client("apigateway")
    api_id = _new_api(
        ctx, apigw, name=ctx.unique_name("sim2real-grag-"), description="list and read agree",
        version="v3", apiKeySource="AUTHORIZER", minimumCompressionSize=2048,
        binaryMediaTypes=["image/png"], endpointConfiguration={"types": ["REGIONAL"]}, tags={"sim2real": CHECK},
    )

    deadline = time.monotonic() + _wait_cap(ctx, 60.0)
    while True:
        api = _paced(ctx, lambda: apigw.get_rest_api(restApiId=api_id))
        read = {f: api[f] for f in _SHARED if f in api}
        items = _listed(ctx, apigw, lambda item: item["id"] == api_id)
        listed = {f: items[0].get(f) for f in read} if len(items) == 1 else None
        if listed == read or time.monotonic() >= deadline:
            break
        time.sleep(2)

    assert len(items) == 1, f"GetRestApis listed the API {len(items)} times"
    assert {"id", "name", "description", "version", "apiKeySource", "binaryMediaTypes"} <= set(read), (
        f"GetRestApi carried only {sorted(read)!r}"
    )
    differ = {f: {"read": read[f], "list": listed[f]} for f in read if listed[f] != read[f]}
    assert differ == {}, f"GetRestApis disagrees with GetRestApi on {differ!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
