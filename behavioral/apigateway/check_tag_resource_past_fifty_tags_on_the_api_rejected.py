"""tag-resource-past-fifty-tags-on-the-api-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-past-fifty-tags-on-the-api-rejected"
GROUP = "tagging"
SERVICES = ["apigateway"]

_EXPECTED_CODE = "BadRequestException"
_EXPECTED_MESSAGE = "Up to 50 tags can be set per resource. No tags were set on this request."


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


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; a success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The 50-tag limit counts the tags a REST API already carries: three new keys onto 48 are
    refused and change nothing, and the same call is accepted once one held key is removed.
    """
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-t50-")
    api_id = _paced(
        ctx, lambda: apigw.create_rest_api(name=name, endpointConfiguration={"types": ["REGIONAL"]})
    )["id"]
    ctx.on_cleanup(_delete_api(apigw, api_id))
    arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    def listed():
        return apigw.get_tags(resourceArn=arn)["tags"]

    held = {f"k{i:02d}": "v" for i in range(48)}
    apigw.tag_resource(resourceArn=arn, tags=held)
    got = _settled(ctx, listed, held, "GetTags showed the 48 tags")
    assert got == held, f"after tagging 48 keys the API lists {len(got)} tag(s), expected the 48 sent"

    extra = {"x1": "v", "x2": "v", "x3": "v"}
    got = _refusal(lambda: apigw.tag_resource(resourceArn=arn, tags=extra))
    assert got == (_EXPECTED_CODE, _EXPECTED_MESSAGE), (
        f"three new keys onto 48 gave {got!r}, expected {(_EXPECTED_CODE, _EXPECTED_MESSAGE)!r}"
    )

    # Untagging one held key is the later control: once it is gone from the list, a key from the
    # refused call would be listed too.
    apigw.untag_resource(resourceArn=arn, tagKeys=["k00"])
    fewer = {k: v for k, v in held.items() if k != "k00"}
    got = _settled(ctx, listed, fewer, "GetTags showed k00 removed")
    assert got == fewer, (
        f"after the refused call and untagging k00 the API lists {sorted(set(got) - set(fewer))!r} "
        f"beyond the 47 held keys and lacks {sorted(set(fewer) - set(got))!r}"
    )

    apigw.tag_resource(resourceArn=arn, tags=extra)
    full = {**fewer, **extra}
    got = _settled(ctx, listed, full, "GetTags showed the 50 tags")
    assert got == full, f"the same three keys onto 47 left the API with {len(got)} tag(s), expected exactly 50"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
