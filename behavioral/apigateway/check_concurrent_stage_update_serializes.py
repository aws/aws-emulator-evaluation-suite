"""concurrent-stage-update-serializes."""
from __future__ import annotations

import random
import string

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-stage-update-serializes"
GROUP = 'concurrency'
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

def _put_mock_method(ag, api_id, resource_id, http_method="GET"):
    """A fully integrated MOCK method (deployable without a real backend)."""
    ag.put_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                  authorizationType="NONE")
    ag.put_integration(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                       type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'})
    ag.put_method_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                           statusCode="200")
    ag.put_integration_response(restApiId=api_id, resourceId=resource_id, httpMethod=http_method,
                                statusCode="200", responseTemplates={"application/json": '{"message": "ok"}'})

def _err_code(result):
    """Extract the botocore error code from a run_concurrent() result slot, or the
    exception's class name for another exception type, or None for a success."""
    if isinstance(result, ClientError):
        return result.response.get("Error", {}).get("Code")
    if isinstance(result, BaseException):
        return type(result).__name__
    return None

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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateStage calls setting the same stage's description to different values each
    succeed or fail with ConflictException, and GetStage then returns exactly one of the two values."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="res")["id"]
    _put_mock_method(ag, api_id, resource_id)
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    stage_name = f"s{_unique_token()}"
    ag.create_stage(
        restApiId=api_id,
        stageName=stage_name,
        deploymentId=deployment_id,
        description="initial-description",
    )

    candidates = ["updated-by-racer-alpha", "updated-by-racer-beta"]

    def _update(desc):
        return ag.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[{"op": "replace", "path": "/description", "value": desc}],
        )

    results = _run_concurrent([lambda d=d: _update(d) for d in candidates])

    successes = _concurrent_successes(results)
    assert successes >= 1, "at least one of the two concurrent UpdateStage calls must succeed"
    for r in results:
        code = _err_code(r)
        if code is not None:
            assert code == "ConflictException", (
                f"expected a losing concurrent UpdateStage to fail with ConflictException, got {code}"
            )
            message = r.response.get("Error", {}).get("Message")
            assert message == "Unable to complete operation due to concurrent modification. Please try again later.", (
                f"unexpected ConflictException message {message!r}"
            )

    final = ag.get_stage(restApiId=api_id, stageName=stage_name)
    assert final["description"] in set(candidates), (
        f"final stage description {final['description']!r} is not one of the two whole "
        f"submitted values {candidates!r} - indicates a corrupted/partial merge, or a "
        f"reported success that was never actually applied"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
