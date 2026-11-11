"""input-sources-with-identical-tags-are-distinct-and-deleted-individually."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "input-sources-with-identical-tags-are-distinct-and-deleted-individually"
GROUP = "input-sources"
SERVICES = ["resiliencehubv2"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "resiliencehub.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _invoker_role(ctx, iam) -> str:
    """An IAM role resiliencehub may assume, deleted at teardown."""
    name = ctx.unique_name("sim2real-behav-rhv2-role-")
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return name


def _create_service(ctx, rh, role: str, **kwargs) -> dict:
    """CreateService, retried only while IAM has not yet made the new invoker role assumable."""
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-rhv2-svc-"))
    unassumable = (
        f"Cannot assume invoker role '{role}'. Ensure the role exists and its trust policy "
        "allows access."
    )
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            service = rh.create_service(
                regions=[ctx.region], permissionModel={"invokerRoleName": role}, **kwargs
            )["service"]
            break
        except ClientError as exc:
            if exc.response["Error"].get("Message") != unassumable:
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("invoker role becoming assumable: the run budget ended first; not graded") from exc
                raise
        # IAM propagation exposes no condition to poll; the retry above is what waits.
        time.sleep(5)
    arn = service["serviceArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_service(serviceArn=arn), "ResourceNotFoundException"))
    return service


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two tag input sources with identical tags are two input sources; deleting one leaves the
    other, and deleting it again answers ResourceNotFoundException naming it.
    """
    rh = ctx.client("resiliencehubv2")
    role = _invoker_role(ctx, ctx.client("iam"))
    arn = _create_service(ctx, rh, role)["serviceArn"]
    config = {"resourceTags": [{"key": "app", "values": ["storefront"]}]}
    ids = []
    for _ in range(2):
        source_id = rh.create_input_source(serviceArn=arn, resourceConfiguration=config)["inputSourceId"]
        ids.append(source_id)
        # An input source outlives its service, so it is deleted on its own.
        ctx.on_cleanup(_teardown(lambda s=source_id: rh.delete_input_source(serviceArn=arn, inputSourceId=s),
                                 "ResourceNotFoundException"))
    assert ids[0] != ids[1], "each create must mint its own input source id"
    listed = {s["inputSourceId"]: (s["type"], s["resourceTags"]) for s in rh.list_input_sources(serviceArn=arn)["inputSourceSummaries"]}
    want = ("TAGS", config["resourceTags"])
    assert listed == {ids[0]: want, ids[1]: want}, f"expected both TAGS sources, got {listed!r}"

    rh.delete_input_source(serviceArn=arn, inputSourceId=ids[0])
    remaining = [s["inputSourceId"] for s in rh.list_input_sources(serviceArn=arn)["inputSourceSummaries"]]
    assert remaining == [ids[1]], f"expected only the second source, got {remaining!r}"
    code, message = _error(lambda: rh.delete_input_source(serviceArn=arn, inputSourceId=ids[0]))
    assert (code, message) == ("ResourceNotFoundException", f"Input source not found: {ids[0]}"), (
        f"DeleteInputSource twice: {code}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
