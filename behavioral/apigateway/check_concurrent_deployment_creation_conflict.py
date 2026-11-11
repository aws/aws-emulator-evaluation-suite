"""concurrent-deployment-creation-conflict."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-deployment-creation-conflict"
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
        tags={"sim2real": "concurrent-deployment-creation-conflict"},
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

def _err(result):
    """(code, message) of a failed run_concurrent() result slot: the botocore error, or the
    exception's class name for another exception type. A success slot is not an error."""
    if isinstance(result, ClientError):
        err = result.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    if isinstance(result, BaseException):
        return type(result).__name__, str(result)
    raise AssertionError(f"expected a failed racer, got a success {result!r}")

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Overlapping CreateDeployment calls re-pointing the same stage serialize: each loser fails with
    ConflictException and AWS's exact in-progress message, at least one succeeds, and the stage ends on
    exactly one of the created deployment ids."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    root_id = _root_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="res")["id"]
    _put_mock_method(ag, api_id, resource_id)
    stage_name = f"s{_unique_token()}"
    ag.create_deployment(restApiId=api_id, stageName=stage_name)

    n = 5

    def _redeploy(i):
        return ag.create_deployment(
            restApiId=api_id, stageName=stage_name, description=f"racer-{i}"
        )

    results = _run_concurrent([lambda i=i: _redeploy(i) for i in range(n)])

    successes = _concurrent_successes(results)
    assert successes >= 1, (
        "at least one of the concurrent CreateDeployment calls targeting the same stage must succeed"
    )
    conflict_message = (
        f"Another Deployment is in progress for rest api with id {api_id} . Please try again later."
    )
    for r in results:
        if not isinstance(r, BaseException):
            continue
        code, message = _err(r)
        assert code == "ConflictException", (
            f"expected a contending CreateDeployment to fail with ConflictException, got {code}"
        )
        assert message == conflict_message, f"unexpected ConflictException message {message!r}"

    success_ids = {r["id"] for r in results if not isinstance(r, BaseException)}

    # Independent reads, spaced out: a torn/flapping pointer would show up as more
    # than one observed deploymentId, not just a wrong one.
    observed_deployment_ids = set()
    for _ in range(3):
        stage = ag.get_stage(restApiId=api_id, stageName=stage_name)
        observed_deployment_ids.add(stage["deploymentId"])
        time.sleep(0.5)
    assert len(observed_deployment_ids) == 1, (
        f"stage deploymentId was not stable across independent reads: "
        f"{observed_deployment_ids!r} - torn/flapping state"
    )
    final_deployment_id = next(iter(observed_deployment_ids))
    assert final_deployment_id in success_ids, (
        f"stage deploymentId {final_deployment_id!r} must be one of the successfully "
        f"created deployments {success_ids!r} - not orphaned or hybrid"
    )
    # The winning deployment must actually exist (not a corrupted/dangling reference).
    winning_deployment = ag.get_deployment(restApiId=api_id, deploymentId=final_deployment_id)
    assert winning_deployment["id"] == final_deployment_id, (
        f"GetDeployment for the winning id {final_deployment_id!r} returned a mismatched "
        f"id {winning_deployment.get('id')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
