"""api-cache-refuses-update-and-delete-while-creating."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-cache-refuses-update-and-delete-while-creating"
GROUP = "state-machine"
SERVICES = ["appsync"]

#: Fresh caches tried before the check gives up on observing the CREATING window.
_ATTEMPTS = 3
#: Wall bound on all attempts; the runner's remaining time bounds it further.
_DEADLINE_S = 120.0
#: TTL validation answers before the state check, so an out-of-range TTL is refused for its value.
_TTL_REFUSAL = (
    "BadRequestException",
    "TTL value cannot be smaller than 1 second and larger than 3600 seconds.",
)
_REFUSALS = {
    "UpdateApiCacheTtl": _TTL_REFUSAL,
    "UpdateApiCache": (
        "BadRequestException",
        "The cache is not yet available. Please wait until it becomes available.",
    ),
    "DeleteApiCache": (
        "BadRequestException",
        "Cannot delete cache as it is either not available or its creation failed.",
    ),
}

#: The code _outcome reports for a call the target accepted.
_ACCEPTED = "accepted"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CREATING API cache keeps its requested config and refuses UpdateApiCache (not yet
    available, or a TTL above 3600 s, which is checked first) and DeleteApiCache (not available)
    with BadRequestException: deletion and reconfiguration are legal only once it is AVAILABLE."""
    svc = ctx.client("appsync")
    deadline = time.monotonic() + _bound(ctx, _DEADLINE_S)
    calls = {
        "UpdateApiCacheTtl": lambda a: svc.update_api_cache(
            apiId=a, ttl=7200, apiCachingBehavior="FULL_REQUEST_CACHING", type="LARGE"
        ),
        "UpdateApiCache": lambda a: svc.update_api_cache(
            apiId=a, ttl=600, apiCachingBehavior="PER_RESOLVER_CACHING", type="SMALL"
        ),
        "DeleteApiCache": lambda a: svc.delete_api_cache(apiId=a),
    }
    pending = list(calls)
    tried = []
    for _ in range(_ATTEMPTS):
        if not pending or time.monotonic() >= deadline:
            break
        api_id = svc.create_graphql_api(
            name=ctx.unique_name("sim2real-behav-appsync-cache-"),
            authenticationType="API_KEY",
            tags={"sim2real": CHECK, "sim2real:managed": "true"},
        )["graphqlApi"]["apiId"]
        ctx.on_cleanup(lambda a=api_id: _ignore_not_found(lambda: svc.delete_graphql_api(apiId=a)))
        svc.create_api_cache(
            apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
        for op in list(pending):
            cache = svc.get_api_cache(apiId=api_id)["apiCache"]
            if cache["status"] != "CREATING":
                tried.append(f"{api_id}: cache {cache['status']} before {op}")
                break
            _assert_requested_config(cache)
            code, message = _outcome(lambda: calls[op](api_id))
            if op == "UpdateApiCacheTtl":
                assert (code, message) == _TTL_REFUSAL, (
                    f"UpdateApiCache with ttl=7200 answered {code!r} {message!r}, "
                    f"expected {_TTL_REFUSAL!r}"
                )
                after = svc.get_api_cache(apiId=api_id)["apiCache"]
                _assert_requested_config(after)
                if after["status"] == "CREATING":
                    pending.remove(op)
                    continue
                tried.append(f"{api_id}: cache {after['status']} after the ttl=7200 update")
                break
            if (code, message) == _REFUSALS[op]:
                after = svc.get_api_cache(apiId=api_id)["apiCache"]
                _assert_requested_config(after)
                pending.remove(op)
                continue
            still = _cache_status(svc, api_id)
            assert still != "CREATING", (
                f"{op} on a cache that stayed CREATING answered {code!r} {message!r}, "
                f"expected {_REFUSALS[op]!r}"
            )
            assert code == _ACCEPTED, (
                f"{op} answered {code!r} {message!r} once the cache was {still!r}"
            )
            tried.append(f"{api_id}: {op} answered {code!r} after the cache left CREATING ({still!r})")
            break
    assert not pending, (
        f"never observed the refusal of {pending} while the cache was CREATING in "
        f"{_ATTEMPTS} fresh caches: {tried!r}"
    )


def _assert_requested_config(cache: dict) -> None:
    """The cache still holds the config CreateApiCache asked for."""
    got = (cache["ttl"], cache["apiCachingBehavior"], cache["type"])
    assert got == (300, "FULL_REQUEST_CACHING", "SMALL"), (
        f"cache config is {got!r}, expected the requested (300, 'FULL_REQUEST_CACHING', 'SMALL')"
    )


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, the response) when it is accepted."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _cache_status(svc, api_id: str) -> str | None:
    try:
        return svc.get_api_cache(apiId=api_id)["apiCache"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _bound(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 30.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
