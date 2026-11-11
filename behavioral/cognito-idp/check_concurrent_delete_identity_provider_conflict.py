"""concurrent-delete-identity-provider-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-delete-identity-provider-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIdentityProvider racing UpdateIdentityProvider calls leaves the provider either fully
    intact with well-formed details or gone, DescribeIdentityProvider then answering
    ResourceNotFoundException with the exact message."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    provider_name = "LoginWithAmazon"

    def _ensure_provider():
        try:
            idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=provider_name)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        idp.create_identity_provider(
            UserPoolId=pool_id,
            ProviderName=provider_name,
            ProviderType=provider_name,
            ProviderDetails={
                "client_id": "sim2real-amzn-client-id",
                "client_secret": "sim2real-amzn-client-secret",
                "authorize_scopes": "profile",
            },
        )

    # A losing writer gets ConcurrentModificationException, ResourceNotFoundException (once the
    # delete won) or an InvalidParameterException reporting a version conflict; any other
    # InvalidParameterException fails.
    for attempt in range(3):
        _ensure_provider()
        fns = [
            (lambda: idp.delete_identity_provider(UserPoolId=pool_id, ProviderName=provider_name))
            for _ in range(3)
        ] + [
            (lambda i=i, attempt=attempt: idp.update_identity_provider(
                UserPoolId=pool_id,
                ProviderName=provider_name,
                AttributeMapping={"username": f"racer-{attempt}-{i}"},
            ))
            for i in range(5)
        ]
        results = _race(fns)
        successes = [r for r, err, _msg in results if err is None]
        [err for _, err, _msg in results if err is not None]
        others = [
            (err, msg) for _, err, msg in results if err is not None and not _is_conflict_loser(err, msg)
        ]
        assert not others, f"unexpected errors racing delete/update identity provider: {others}"
        assert len(successes) >= 1, "no delete/update call succeeded under contention"
        if any(_is_conflict_loser(err, msg) for _, err, msg in results if err is not None):
            break
    else:
        raise AssertionError(
            "no ConcurrentModificationException/ResourceNotFoundException/conflict"
            " InvalidParameterException observed across 3 attempts of racing"
            " DeleteIdentityProvider against UpdateIdentityProvider"
        )

    try:
        final = idp.describe_identity_provider(
            UserPoolId=pool_id, ProviderName=provider_name
        )["IdentityProvider"]
        assert final["ProviderType"] == "LoginWithAmazon", (
            f"provider type corrupted after race: expected LoginWithAmazon, got {final['ProviderType']!r}"
        )
        assert final["ProviderDetails"].get("client_id") == "sim2real-amzn-client-id" or (
            final["AttributeMapping"].get("username", "").startswith("racer-")
        ), (
            "identity provider survived the race but is neither the original config nor a "
            f"winning racer's update: ProviderDetails={final['ProviderDetails']!r} "
            f"AttributeMapping={final['AttributeMapping']!r}"
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            "identity provider left in an unexpected error state after the race"
        )
        assert e.response["Error"].get("Message") == (
            f"Identity provider {provider_name} for tenantId {pool_id} does not exist."
        ), f"expected the exact ResourceNotFoundException message, got {e.response['Error'].get('Message')!r}"


from botocore.exceptions import ClientError


def _call(fn):
    try:
        return fn(), None, None
    except ClientError as e:
        return None, e.response["Error"]["Code"], e.response["Error"].get("Message", "")


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(_call, fn) for fn in fns]
        return [f.result() for f in futures]


_CONFLICT_KEYWORDS = ("concurrent", "modif", "conflict", "stale", "changed", "version")


def _is_conflict_loser(code: str, message: str | None) -> bool:
    """True if `code`/`message` represents a legitimate losing-writer outcome for this race:
    ConcurrentModificationException, ResourceNotFoundException (the resource was deleted by a
    winning racer), or an InvalidParameterException whose message reports the underlying
    version/conflict rejection rather than an unrelated malformed-request error."""
    if code in ("ConcurrentModificationException", "ResourceNotFoundException"):
        return True
    if code == "InvalidParameterException" and message:
        low = message.lower()
        return any(kw in low for kw in _CONFLICT_KEYWORDS)
    return False


def _wait_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
