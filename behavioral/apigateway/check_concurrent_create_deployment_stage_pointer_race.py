"""concurrent-create-deployment-stage-pointer-race."""
from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-deployment-stage-pointer-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateDeployment calls that update the same stage converge to one pointer."""
    apigw = ctx.client("apigateway")
    stage_name = "race"

    api_id = _create_deployable_api(ctx, apigw)

    # baseline deployment/stage so the race is against an already-existing pointer
    baseline = apigw.create_deployment(
        restApiId=api_id, stageName=stage_name, description="baseline"
    )
    baseline_id = baseline["id"]

    n_racers = 5

    def _redeploy(i: int) -> str:
        # real API Gateway throttles concurrent CreateDeployment calls (TooManyRequestsException)
        # and refuses one that overlaps another deployment of the same API (ConflictException);
        # retry both with jittered backoff so every racer lands its deployment.
        attempt = 0
        while True:
            try:
                resp = apigw.create_deployment(
                    restApiId=api_id, stageName=stage_name, description=f"race-{i}"
                )
                return resp["id"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                attempt += 1
                if code not in ("TooManyRequestsException", "ConflictException") or attempt >= 10:
                    raise
                time.sleep(min(1.0, 0.1 * (2 ** attempt)) + random.uniform(0, 0.1))

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        race_ids = list(pool.map(_redeploy, range(n_racers)))

    assert len(set(race_ids)) == n_racers, "each concurrent CreateDeployment must mint a distinct id"

    all_deployments = {
        d["id"] for d in apigw.get_deployments(restApiId=api_id)["items"]
    }
    assert baseline_id in all_deployments, (
        f"baseline deployment {baseline_id} missing from GetDeployments {all_deployments}"
    )
    for rid in race_ids:
        assert rid in all_deployments, f"deployment {rid} missing from GetDeployments"

    # the stage must converge to exactly one of the raced deployments (last-writer-wins),
    # and repeated reads must agree (no torn/flapping pointer state)
    stage_view_1 = apigw.get_stage(restApiId=api_id, stageName=stage_name)["deploymentId"]
    stage_view_2 = apigw.get_stage(restApiId=api_id, stageName=stage_name)["deploymentId"]
    assert stage_view_1 == stage_view_2, "GetStage returned inconsistent deploymentId across reads"
    assert stage_view_1 in race_ids, (
        f"stage deploymentId {stage_view_1} did not converge to one of the raced deployments {race_ids}"
    )

    # explicit UpdateStage pointer change is also observed deterministically
    apigw.update_stage(
        restApiId=api_id,
        stageName=stage_name,
        patchOperations=[{"op": "replace", "path": "/deploymentId", "value": baseline_id}],
    )
    reverted = apigw.get_stage(restApiId=api_id, stageName=stage_name)["deploymentId"]
    assert reverted == baseline_id, (
        f"expected UpdateStage to repoint deploymentId to baseline {baseline_id}, got {reverted}"
    )


def _create_deployable_api(ctx: Any, apigw: Any) -> str:
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-restapi-"), tags={"sim2real": CHECK}
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    resources = apigw.get_resources(restApiId=api_id)["items"]
    root_id = next(r["id"] for r in resources if r["path"] == "/")

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": ""},
    )
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
