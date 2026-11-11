"""create-deployment-nonexistent-thing-group-target-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-nonexistent-thing-group-target-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeployment against a syntactically valid but never-created IoT thing GROUP ARN is
    rejected with ValidationException, the same as for an individual thing; the same call
    against a real thing group succeeds."""
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bogus_group = ctx.unique_name("sim2real-ggv2-missing-tg-")
    bogus_target = f"arn:aws:iot:{ctx.region}:{account_id}:thinggroup/{bogus_group}"

    code, message = _error_code(lambda: ggv2.create_deployment(targetArn=bogus_target))
    assert code == "ValidationException", code
    assert message == "Invalid Input: Target not found", message

    # Effect absent: no deployment record was created against the bogus target.
    deployments = ggv2.list_deployments(targetArn=bogus_target, historyFilter="ALL")["deployments"]
    assert deployments == [], deployments

    # Restore: create the exact thing group the target ARN named, so the retry below is the
    # identical call (same targetArn), not merely a call against some other, real group.
    restored_arn = iot.create_thing_group(thingGroupName=bogus_group)["thingGroupArn"]
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=bogus_group))
    assert restored_arn == bogus_target, (restored_arn, bogus_target)

    created = ggv2.create_deployment(targetArn=bogus_target)
    deployment_id = created["deploymentId"]
    ctx.on_cleanup(lambda: _cleanup_deployment(ggv2, deployment_id))
    status = ggv2.get_deployment(deploymentId=deployment_id)["deploymentStatus"]
    assert status == "ACTIVE", status


def _cleanup_deployment(ggv2, deployment_id: str) -> None:
    _try(lambda: ggv2.cancel_deployment(deploymentId=deployment_id))
    _try(lambda: ggv2.delete_deployment(deploymentId=deployment_id))


def _try(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    a target ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ValidationException, but the call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
