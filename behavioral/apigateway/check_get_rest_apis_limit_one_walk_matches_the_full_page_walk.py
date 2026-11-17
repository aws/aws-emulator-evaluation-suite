"""get-rest-apis-limit-one-walk-matches-the-full-page-walk."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-rest-apis-limit-one-walk-matches-the-full-page-walk"
GROUP = "pagination"
SERVICES = ["apigateway"]

_APIS = 3
_PAGE = 1
_FULL_PAGE = 500  # the largest limit GetRestApis accepts
_PAGE_CAP = 5000  # a walk that never drops position fails instead of spinning


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


def _walk(ctx, apigw, limit: int) -> list[list[str]]:
    """Every GetRestApis page in order, following position until a page carries none."""
    pages: list[list[str]] = []
    kwargs = {"limit": limit}
    while True:
        resp = _paced(ctx, lambda: apigw.get_rest_apis(**kwargs))
        pages.append([item["id"] for item in resp.get("items", [])])
        position = resp.get("position")
        if not position:
            return pages
        assert len(pages) < _PAGE_CAP, f"GetRestApis still returned a position after {len(pages)} pages"
        kwargs["position"] = position


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRestApis walked at limit=1 to its last page lists the check's REST APIs once each, exactly
    as the walk at limit=500 lists them.
    """
    apigw = ctx.client("apigateway")
    stem = ctx.unique_name("sim2real-grpw-")
    own = []
    for i in range(_APIS):
        api_id = _paced(ctx, lambda i=i: apigw.create_rest_api(
            name=f"{stem}-{i}", endpointConfiguration={"types": ["REGIONAL"]}
        ))["id"]
        ctx.on_cleanup(_delete_api(apigw, api_id))
        own.append(api_id)
    own.sort()

    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        whole = [i for page in _walk(ctx, apigw, _FULL_PAGE) for i in page if i in own]
        small = _walk(ctx, apigw, _PAGE)
        paged = [i for page in small for i in page if i in own]
        if sorted(whole) == own and sorted(paged) == own:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the run budget ended before both GetRestApis walks listed the APIs")
            break
        time.sleep(2)

    assert sorted(whole) == own, f"the limit={_FULL_PAGE} walk listed {sorted(whole)!r}, expected {own!r}"
    sizes = [len(page) for page in small]
    assert all(size <= _PAGE for size in sizes), f"a limit={_PAGE} page held more: page sizes {sizes!r}"
    assert len(paged) == len(set(paged)), f"the limit={_PAGE} walk listed a REST API twice: {paged!r}"
    assert sorted(paged) == sorted(whole), (
        f"the limit={_PAGE} walk listed {sorted(paged)!r}, the limit={_FULL_PAGE} walk {sorted(whole)!r}"
    )
    assert len(small) >= _APIS, f"{_APIS} REST APIs at limit={_PAGE} gave only {len(small)} page(s)"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
