"""tag-resource-second-call-adds-keys-and-retagging-replaces-the-value."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-second-call-adds-keys-and-retagging-replaces-the-value"
GROUP = "tagging"
SERVICES = ["apigateway"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _paced(ctx, fn):
    """fn(), retried while API Gateway paces the call on the account."""
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _delete_api(apigw, api_id: str):
    """A cleanup deleting the REST API, waited through DeleteRestApi's per-account pacing."""

    def run_undo():
        deadline = time.monotonic() + 100.0
        while True:
            try:
                apigw.delete_rest_api(restApiId=api_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NotFoundException":
                    return
                if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                    raise
            time.sleep(5)

    return run_undo


def _settled(ctx, read, want, what: str):
    """read() polled until it equals want or the wait ends; the last read either way."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        got = read()
        if got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended before {what}")
            return got
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second TagResource adds its key beside the keys already set, and re-tagging a present key
    replaces its value; GetTags returns exactly the merged map each time.
    """
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-trk-")
    api_id = _paced(
        ctx, lambda: apigw.create_rest_api(name=name, endpointConfiguration={"types": ["REGIONAL"]})
    )["id"]
    ctx.on_cleanup(_delete_api(apigw, api_id))
    arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    def listed():
        return apigw.get_tags(resourceArn=arn)["tags"]

    apigw.tag_resource(resourceArn=arn, tags={"team": "blue", "stage": "test"})
    first = {"team": "blue", "stage": "test"}
    got = _settled(ctx, listed, first, "GetTags showed the first two tags")
    assert got == first, f"after tagging team and stage the API lists {got!r}, expected {first!r}"

    apigw.tag_resource(resourceArn=arn, tags={"cost": "lab"})
    merged = {**first, "cost": "lab"}
    got = _settled(ctx, listed, merged, "GetTags showed the merged tags")
    assert got == merged, f"a second TagResource left the API listing {got!r}, expected {merged!r}"

    apigw.tag_resource(resourceArn=arn, tags={"team": "green"})
    replaced = {**merged, "team": "green"}
    got = _settled(ctx, listed, replaced, "GetTags showed the replaced value")
    assert got == replaced, f"re-tagging team left the API listing {got!r}, expected {replaced!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
