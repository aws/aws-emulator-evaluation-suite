"""cache-cluster-enable-flush-lifecycle."""
from __future__ import annotations

import random
import string
import time

from behavioral_harness import tags

CHECK = "cache-cluster-enable-flush-lifecycle"
GROUP = 'deployments-stages'
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

def _poll_until(fn, pred, *, timeout_s, interval_s, description):
    """Poll fn() until pred() is truthy; raise on timeout (never return the failed value)."""
    deadline = time.time() + timeout_s
    last = None
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"{description}; last observed {last!r}")
        time.sleep(interval_s)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling cacheClusterEnabled starts provisioning at once; after the cluster is AVAILABLE,
    FlushStageCache leaves it enabled, settles back to AVAILABLE, and leaves the stage untouched.
    """
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
        cacheClusterEnabled=True,
        cacheClusterSize="0.5",
    )

    started = _poll_until(
        lambda: ag.get_stage(restApiId=api_id, stageName=stage_name),
        lambda s: s.get("cacheClusterStatus") is not None,
        timeout_s=30,
        interval_s=2,
        description="enabling cacheClusterEnabled must kick off the provisioning state machine immediately",
    )
    assert started["cacheClusterEnabled"] is True
    assert started["cacheClusterStatus"] in (
        "CREATE_IN_PROGRESS",
        "AVAILABLE",
    ), f"unexpected cacheClusterStatus right after enabling: {started['cacheClusterStatus']!r}"

    # Provisioning a cache cluster can take several minutes.
    available = _poll_until(
        lambda: ag.get_stage(restApiId=api_id, stageName=stage_name),
        lambda s: s.get("cacheClusterStatus") == "AVAILABLE",
        timeout_s=600,
        interval_s=15,
        description="cache cluster never reached AVAILABLE; a cluster that does not provision is a failure, not a reason to skip",
    )
    assert available["cacheClusterEnabled"] is True

    ag.flush_stage_cache(restApiId=api_id, stageName=stage_name)

    saw_transient_or_available = False
    deadline = time.time() + 180
    settled = None
    while True:
        settled = ag.get_stage(restApiId=api_id, stageName=stage_name)
        status = settled.get("cacheClusterStatus")
        if status in ("FLUSH_IN_PROGRESS", "AVAILABLE"):
            saw_transient_or_available = True
        if status == "AVAILABLE" and saw_transient_or_available:
            break
        if time.time() >= deadline:
            raise AssertionError(
                f"cache cluster did not settle back to AVAILABLE after FlushStageCache; "
                f"last cacheClusterStatus={status!r}"
            )
        time.sleep(5)

    assert settled["cacheClusterStatus"] == "AVAILABLE"
    assert settled["cacheClusterEnabled"] is True, "FlushStageCache must not disable caching"
    assert settled["deploymentId"] == deployment_id, (
        "FlushStageCache must not change the deployed deploymentId"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
