"""service-function-update-changes-only-the-named-fields."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-function-update-changes-only-the-named-fields"
GROUP = "service-functions"
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
    """UpdateServiceFunction with only a criticality keeps the function's name and description; a
    deleted function then answers ResourceNotFoundException naming its id.
    """
    rh = ctx.client("resiliencehubv2")
    role = _invoker_role(ctx, ctx.client("iam"))
    arn = _create_service(ctx, rh, role)["serviceArn"]
    created = rh.create_service_function(serviceArn=arn, name="order intake", description="accepts orders",
                                         criticality="PRIMARY")["serviceFunction"]
    fid = created["serviceFunctionId"]
    assert (created["source"], created["resourceCount"]) == ("USER", 0), f"a new function: {created!r}"

    rh.update_service_function(serviceArn=arn, serviceFunctionId=fid, criticality="SUPPLEMENTAL")
    listed = {f["serviceFunctionId"]: f for f in rh.list_service_functions(serviceArn=arn)["serviceFunctions"]}
    got = {k: listed[fid].get(k) for k in ("name", "description", "criticality")}
    want = {"name": "order intake", "description": "accepts orders", "criticality": "SUPPLEMENTAL"}
    assert got == want, f"expected {want!r}, got {got!r}"

    rh.update_service_function(serviceArn=arn, serviceFunctionId=fid, name="order capture")
    listed = {f["serviceFunctionId"]: f for f in rh.list_service_functions(serviceArn=arn)["serviceFunctions"]}
    got = {k: listed[fid].get(k) for k in ("name", "description", "criticality")}
    assert got == dict(want, name="order capture"), f"a rename keeps the other fields, got {got!r}"

    rh.delete_service_function(serviceArn=arn, serviceFunctionId=fid)
    code, message = _error(lambda: rh.update_service_function(serviceArn=arn, serviceFunctionId=fid,
                                                              criticality="PRIMARY"))
    assert (code, message) == ("ResourceNotFoundException", f"Service function not found: {fid}"), (
        f"UpdateServiceFunction after delete: {code}: {message!r}"
    )
    assert rh.list_service_functions(serviceArn=arn)["serviceFunctions"] == [], "the function must be gone"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
