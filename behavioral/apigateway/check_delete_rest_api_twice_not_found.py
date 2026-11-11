"""delete-rest-api-twice-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-rest-api-twice-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _throttle_retry(fn, *, time_left=None, timeout_s=150.0):
    """Call fn(), retrying DeleteRestApi's account-level throttle (~1 request per 30 s) every 2 s
    to a deadline: an empty bucket answers TooManyRequestsException before AWS checks whether the
    api exists. Any other error, or the last throttle at the deadline, propagates."""
    if time_left is not None:
        timeout_s = max(1.0, min(timeout_s, time_left - 5.0))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _cleanup_delete(ag, api_id):
    try:
        _throttle_retry(lambda: ag.delete_rest_api(restApiId=api_id))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteRestApi on the same restApiId is not an idempotent success: once the throttle
    lets it through it reports NotFoundException with AWS's exact message, and a throttle that
    never clears fails the check rather than standing in for the refusal."""
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    # Register teardown BEFORE the assertions: if the DeleteRestApi throttle bucket never
    # refills within budget the first delete stays throttled and the check fails, so without
    # this the RestApi would leak with nothing to reap it.
    ctx.on_cleanup(lambda: _cleanup_delete(ag, api_id))
    try:
        _throttle_retry(lambda: ag.delete_rest_api(restApiId=api_id), time_left=ctx.time_left())
    except ClientError as exc:
        # The bucket is account-global and shared with every other apigateway check, so a
        # sustained throttle means the delete->second-delete sequence under test never started.
        raise AssertionError(
            f"expected the first DeleteRestApi to succeed, got {exc.response.get('Error')}"
        ) from exc
    not_found_message = f"Invalid API identifier specified {ctx.account}:{api_id}"

    # Independent read (GetRestApi, not the delete under test): the api must genuinely be gone,
    # not merely have returned a 200 from DeleteRestApi.
    read_code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert read_code == "NotFoundException", (
        f"expected GetRestApi to report NotFoundException right after the first delete, got {read_code}"
    )
    assert message == not_found_message, f"unexpected GetRestApi message {message!r}"

    code, message = _error(
        lambda: _throttle_retry(lambda: ag.delete_rest_api(restApiId=api_id), time_left=ctx.time_left())
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException on a second DeleteRestApi for the same "
        f"restApiId - never a silent idempotent success, got {code}"
    )
    assert message == not_found_message, f"unexpected NotFoundException message {message!r}"

    # Terminal assertion is an independent read at the destination, not the mutating delete
    # itself: a rejected second delete must not have resurrected the api either.
    read_code, message = _error(lambda: ag.get_rest_api(restApiId=api_id))
    assert read_code == "NotFoundException", (
        f"api resurfaced after a rejected repeat DeleteRestApi, GetRestApi returned {read_code}"
    )
    assert message == not_found_message, f"unexpected GetRestApi message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
