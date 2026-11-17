"""create-resource-nonexistent-parent-rejected."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-nonexistent-parent-rejected"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_rest_api(apigw, api_id, *, attempts=10):
    """DeleteRestApi, retried on the control-plane's TooManyRequestsException; NotFoundException
    means it is already gone."""
    for attempt in range(attempts):
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource attaches a child under an existing parentId; a nonexistent parentId
    on an otherwise valid REST API is rejected with NotFoundException and creates nothing."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    # error boundary: restApiId is valid, parentId is not -> NotFoundException, nothing created
    before_ids = {r["id"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    code, message = _error(
        lambda: apigw.create_resource(restApiId=api_id, parentId="nonexistent0", pathPart="widgets")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}: {message!r}"
    assert message == "Invalid Resource identifier specified", f"unexpected message {message!r}"
    after_ids = {r["id"] for r in apigw.get_resources(restApiId=api_id)["items"]}
    assert after_ids == before_ids, (
        f"expected no resource created on the failed parentId, before={sorted(before_ids)!r} "
        f"after={sorted(after_ids)!r}"
    )

    # positive control: the same pathPart under the real root parentId succeeds
    created = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="widgets")
    assert created["path"] == "/widgets", f"expected path /widgets, got {created['path']!r}"
    assert created["parentId"] == root_id, f"expected parentId {root_id!r}, got {created['parentId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
