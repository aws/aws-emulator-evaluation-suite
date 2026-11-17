"""untag-resource-of-fresh-keys-restores-the-rest-api-tags-listed-before."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-of-fresh-keys-restores-the-rest-api-tags-listed-before"
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
    """TagResource of two keys the REST API did not carry, then UntagResource of those keys, leaves
    GetTags with exactly the tags it listed before, creation tags included.
    """
    apigw = ctx.client("apigateway")
    created = {"sim2real": CHECK, "owner": "lab"}
    api_id = _new_api(ctx, apigw, name=ctx.unique_name("sim2real-agf-"), tags=dict(created))
    arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    before = _tags_until(ctx, apigw, arn, created)
    assert before == created, f"a REST API created with tags {created!r} lists {before!r}"

    fresh = {"extra-a": "one", "extra-b": "two"}
    _paced(ctx, lambda: apigw.tag_resource(resourceArn=arn, tags=fresh))
    tagged = {**before, **fresh}
    got = _tags_until(ctx, apigw, arn, tagged)
    assert got == tagged, f"after tagging {sorted(fresh)!r} the REST API lists {got!r}, expected {tagged!r}"

    _paced(ctx, lambda: apigw.untag_resource(resourceArn=arn, tagKeys=sorted(fresh)))
    got = _tags_until(ctx, apigw, arn, before)
    assert got == before, f"untagging {sorted(fresh)!r} left {got!r}, expected the earlier set {before!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
