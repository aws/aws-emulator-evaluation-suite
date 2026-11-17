"""untag-resource-after-retagging-a-present-key-removes-it-from-the-rest-api."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-after-retagging-a-present-key-removes-it-from-the-rest-api"
GROUP = "tagging"
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


def _tags_until(ctx, apigw, arn: str, want: dict) -> dict:
    """GetTags repeated until it lists exactly want or the wait runs out; the last map read."""
    deadline = time.monotonic() + _wait_cap(ctx, 60.0)
    while True:
        got = _paced(ctx, lambda: apigw.get_tags(resourceArn=arn)).get("tags", {})
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-tagging a key the REST API already carries and then untagging it removes the key
    outright: the earlier value does not come back.
    """
    apigw = ctx.client("apigateway")
    created = {"sim2real": CHECK, "env": "first"}
    api_id = _new_api(ctx, apigw, name=ctx.unique_name("sim2real-agr-"), tags=dict(created))
    arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    got = _tags_until(ctx, apigw, arn, created)
    assert got == created, f"a REST API created with tags {created!r} lists {got!r}"

    _paced(ctx, lambda: apigw.tag_resource(resourceArn=arn, tags={"env": "second"}))
    replaced = {"sim2real": CHECK, "env": "second"}
    got = _tags_until(ctx, apigw, arn, replaced)
    assert got == replaced, f"re-tagging env left the REST API listing {got!r}, expected {replaced!r}"

    _paced(ctx, lambda: apigw.untag_resource(resourceArn=arn, tagKeys=["env"]))
    rest = {"sim2real": CHECK}
    got = _tags_until(ctx, apigw, arn, rest)
    assert got == rest, f"untagging the re-tagged env left {got!r}, expected {rest!r} with env gone"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
