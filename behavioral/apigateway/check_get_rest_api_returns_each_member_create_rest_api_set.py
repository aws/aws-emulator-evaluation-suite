"""get-rest-api-returns-each-member-create-rest-api-set."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-rest-api-returns-each-member-create-rest-api-set"
GROUP = "representation"
SERVICES = ["apigateway"]


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRestApi, read by the id CreateRestApi returned, gives back each member the create set
    with the value sent.
    """
    apigw = ctx.client("apigateway")
    # Each value differs from the member's default, so a store that ignores it is caught.
    sent = {
        "name": ctx.unique_name("sim2real-agm-"), "description": "members read back",
        "apiKeySource": "AUTHORIZER", "minimumCompressionSize": 1024, "disableExecuteApiEndpoint": True,
        "binaryMediaTypes": ["image/png"], "tags": {"sim2real": CHECK, "owner": "lab"},
    }
    endpoint = {"types": ["REGIONAL"], "ipAddressType": "dualstack"}
    api_id = _new_api(ctx, apigw, endpointConfiguration=endpoint, **sent)

    api = _paced(ctx, lambda: apigw.get_rest_api(restApiId=api_id))
    read = {member: api.get(member) for member in sent}
    differ = {m: {"sent": sent[m], "read": read[m]} for m in sent if read[m] != sent[m]}
    assert differ == {}, f"GetRestApi does not return what CreateRestApi set: {differ!r}"
    got = {k: api.get("endpointConfiguration", {}).get(k) for k in endpoint}
    assert got == endpoint, f"endpointConfiguration reads {got!r} for the sent keys, expected {endpoint!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
