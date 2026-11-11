"""create-documentation-version-duplicate-conflict."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-documentation-version-duplicate-conflict"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) of the ClientError it raises.
    An unexpected success is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the duplicate create to be rejected, but it succeeded: {result!r}")


def _throttle_retry(fn, *, attempts=10, base_delay=15.0, max_delay=35.0):
    """Call fn(), retrying through API Gateway's low account-level control-plane
    throttle. REST-API / documentation mutations share a bucket that refills
    roughly once every ~30s, so the SDK's own short retries can exhaust and
    surface TooManyRequestsException on legitimate calls. Retry with bucket-sized
    backoff over a generous (~5 min) budget; any other error propagates
    immediately, and a success returns fn()'s result. Re-raises the last throttle
    if it never clears within budget."""
    delay = base_delay
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            last = exc
            if i < attempts - 1:
                time.sleep(min(delay, max_delay))
                delay *= 2
    raise last

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = _throttle_retry(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "create-documentation-version-duplicate-conflict"},
    ))["id"]
    ctx.on_cleanup(lambda: _throttle_retry(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a DocumentationVersion whose value already exists must fail with ConflictException.

    A duplicate documentationVersion must not silently overwrite/duplicate the existing one
    (overly-permissive check).
    """
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    version = "1.0.0"
    _throttle_retry(lambda: ag.create_documentation_part(
        restApiId=api_id, location={"type": "API"}, properties=json.dumps({"description": "d"})
    ))
    _throttle_retry(lambda: ag.create_documentation_version(
        restApiId=api_id, documentationVersion=version))

    # Positive control: the version really exists, via an independent read (not just the
    # absence of an exception from the create call above).
    initial = _throttle_retry(lambda: ag.get_documentation_version(
        restApiId=api_id, documentationVersion=version))
    assert initial["version"] == version, (
        f"positive control failed: expected version {version!r} to be readable after create, "
        f"got {initial}"
    )

    code, message = _error(
        lambda: _throttle_retry(lambda: ag.create_documentation_version(
            restApiId=api_id, documentationVersion=version, description="duplicate"
        ))
    )
    # _throttle_retry waits out the ~1-req/30s bucket, so the terminal refusal is graded.
    assert code == "ConflictException", (
        f"expected ConflictException for a duplicate documentationVersion, got {code}"
    )
    assert message == f"Documentation version {version} already exists.", (
        f"unexpected ConflictException message {message!r}"
    )

    versions = _throttle_retry(lambda: ag.get_documentation_versions(restApiId=api_id))["items"]
    matches = [v for v in versions if v["version"] == version]
    assert len(matches) == 1, f"expected exactly 1 version {version!r}, got {len(matches)}"
    assert matches[0].get("description") != "duplicate", (
        "the rejected duplicate create must not have overwritten the original description"
    )

    # Restore: the conflict is the existing version, not the value itself. Once it is
    # removed, the identical call (same version id, same description) must succeed.
    _throttle_retry(lambda: ag.delete_documentation_version(
        restApiId=api_id, documentationVersion=version))
    _throttle_retry(lambda: ag.create_documentation_version(
        restApiId=api_id, documentationVersion=version, description="duplicate"))
    restored = _throttle_retry(lambda: ag.get_documentation_version(
        restApiId=api_id, documentationVersion=version))
    assert restored.get("description") == "duplicate", (
        f"expected the identical call to succeed once the conflicting version was removed, "
        f"got {restored}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
