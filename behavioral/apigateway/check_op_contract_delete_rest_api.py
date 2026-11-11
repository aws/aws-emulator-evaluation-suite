"""op-contract-deleteRestApi."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-deleteRestApi"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRestApi removes the API so GetRestApi subsequently 404s; deleting the same restApiId a
    second time is rejected with NotFoundException, proving the delete effect is not re-applied."""
    apigw = ctx.client("apigateway")

    name = ctx.unique_name("sim2real-behav-")
    created = apigw.create_rest_api(name=name)
    api_id = created["id"]
    # Register cleanup before any assertion that could fail: without this, an early
    # assertion failure (e.g. the name check below) would leak the RestApi, since the
    # happy path's own delete_rest_api() call below would never run.
    ctx.on_cleanup(lambda: _delete_if_present(apigw, api_id))

    fetched = apigw.get_rest_api(restApiId=api_id)
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"

    # DeleteRestApi shares an account-wide throttle bucket refilling at ~1 request per 30s,
    # shared with every other concurrently-running apigateway check in this account, so even
    # this first delete can arrive as TooManyRequestsException. Poll on a cadence no faster
    # than the refill period, and for long enough to outlast contention, to observe the real
    # terminal outcome rather than giving up mid-throttle.
    _delete_retrying_throttle(apigw, api_id)

    err = _client_error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert err.get("Code") == "NotFoundException", f"API still present after delete, got {err.get('Code')!r}"
    assert err.get("Message") == f"Invalid API identifier specified {ctx.account}:{api_id}", (
        f"expected the exact NotFound message from GetRestApi, got {err.get('Message')!r}"
    )

    err = _poll_until_not_throttled(
        lambda: _client_error(lambda: apigw.delete_rest_api(restApiId=api_id))
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException on second delete, got {err.get('Code')!r}"
    assert err.get("Message") == f"Invalid API identifier specified {ctx.account}:{api_id}", (
        f"expected the exact NotFound message from the second DeleteRestApi, got {err.get('Message')!r}"
    )

    err = _client_error(lambda: apigw.get_rest_api(restApiId=api_id))
    assert err.get("Code") == "NotFoundException", f"API resurfaced after a failed repeat delete, got {err.get('Code')!r}"
    assert err.get("Message") == f"Invalid API identifier specified {ctx.account}:{api_id}", (
        f"expected the exact NotFound message after the repeat delete, got {err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_if_present(apigw, api_id):
    from botocore.exceptions import ClientError

    try:
        apigw.delete_rest_api(restApiId=api_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NotFoundException", "TooManyRequestsException"):
            raise


def _delete_retrying_throttle(apigw, api_id, timeout_s: float = 120.0, interval_s: float = 30.0):
    """DeleteRestApi, retrying only TooManyRequestsException until the deadline; any other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return apigw.delete_rest_api(restApiId=api_id)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _poll_until_not_throttled(fn, timeout_s: float = 120.0, interval_s: float = 30.0):
    """Call fn() (which returns an Error dict) until its code is not TooManyRequestsException."""
    deadline = time.monotonic() + timeout_s
    err = fn()
    while err.get("Code") == "TooManyRequestsException" and time.monotonic() < deadline:
        time.sleep(interval_s)
        err = fn()
    return err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

