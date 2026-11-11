"""delete-method-too-many-requests."""
from __future__ import annotations

import random
import string

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-method-too-many-requests"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    """The api's root ('/') resource id."""
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _high_concurrency_client(ctx):
    """Same-identity client with a wide pool and SDK retries off: boto3's default pool (10)
    serializes a burst and masks throttling; with retries off a 429 reaches the caller."""
    cfg = Config(retries={"max_attempts": 1}, max_pool_connections=200)
    return ctx.client("apigateway", config=cfg)

def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))

def _concurrent_errors(results):
    """(code, message) of every failed racer; a non-ClientError failure keeps its class name."""
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            err = r.response.get("Error", {})
            errors.append((err.get("Code"), err.get("Message")))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


_NOT_FOUND_MESSAGE = "Invalid Method identifier specified"
_THROTTLED_MESSAGE = "Too Many Requests"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 70-way concurrent DeleteMethod burst has exactly one winner; each loser gets the exact
    NotFoundException or TooManyRequestsException answer, and the method is then gone."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=root_id, pathPart="throttletarget"
    )["id"]
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )

    raw = _high_concurrency_client(ctx)  # unwrapped + wide pool: genuinely simultaneous
    n = 70

    results = _run_concurrent(
        [
            (lambda: raw.delete_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET"))
            for _ in range(n)
        ],
        timeout_s=120,
    )
    successes = _concurrent_successes(results)
    assert successes == 1, (
        f"expected exactly 1 racer to win the DeleteMethod race, got {successes} "
        f"successes among {n} concurrent calls"
    )
    errors = _concurrent_errors(results)
    assert len(errors) == n - 1, f"expected {n - 1} failed racers, got {len(errors)}"
    for code, message in errors:
        # A loser is either refused because the winner already deleted the method, or throttled
        # by the burst before it reached the method; each answer carries its own exact message.
        if code == "TooManyRequestsException":
            assert message == _THROTTLED_MESSAGE, f"unexpected TooManyRequestsException message {message!r}"
        else:
            assert code == "NotFoundException", (
                f"expected every losing racer to observe NotFoundException (already deleted) "
                f"or TooManyRequestsException, got {errors!r}"
            )
            assert message == _NOT_FOUND_MESSAGE, f"unexpected NotFoundException message {message!r}"

    # Independent read through a different operation: the method is gone, not just reported gone.
    code, message = _error(
        lambda: ag.get_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    )
    assert code == "NotFoundException", (
        f"expected GetMethod on the deleted method to 404 NotFoundException, got {code}"
    )
    assert message == _NOT_FOUND_MESSAGE, f"unexpected GetMethod NotFoundException message {message!r}"

    code, message = _error(
        lambda: ag.delete_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET")
    )
    assert code == "NotFoundException", (
        f"expected a post-race DeleteMethod on the dead method to 404 NotFoundException, got {code}"
    )
    assert message == _NOT_FOUND_MESSAGE, f"unexpected DeleteMethod NotFoundException message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
