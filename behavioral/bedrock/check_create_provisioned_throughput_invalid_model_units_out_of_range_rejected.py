"""create-provisioned-throughput-invalid-model-units-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-provisioned-throughput-invalid-model-units-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProvisionedModelThroughput with modelUnits=0, below the model's minimum of 1, fails
    request validation with ValidationException and the exact modelUnits constraint message, and
    nothing is provisioned under that name."""
    bedrock = ctx.client("bedrock")
    model_id = _first_provisionable_model_arn(bedrock)

    # botocore enforces the model's min-value constraint locally; client-side validation is off
    # so the request reaches the service and its own rejection is observed.
    raw_bedrock = ctx.client("bedrock", config=Config(parameter_validation=False))

    bad_name = ctx.unique_name("sim2real-bedrock-pt-bad-")
    # Provisioned Throughput bills by the hour: registered before the create, so a throughput an
    # accepting target creates under this name is deleted even when the run times out.
    ctx.on_cleanup(lambda: _delete_named_and_wait_gone(bedrock, bad_name, _PT_DELETE_S))

    code, message = _refused_create(
        ctx,
        bedrock,
        bad_name,
        lambda: raw_bedrock.create_provisioned_model_throughput(
            modelUnits=0, provisionedModelName=bad_name, modelId=model_id
        ),
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        "1 validation error detected: Value at 'modelUnits' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: nothing with that name was provisioned
    present = _named(bedrock, bad_name)
    assert not present, f"{bad_name!r} unexpectedly present after a rejected create: {present!r}"


def _refused_create(ctx, bedrock, name, fn):
    """Call a CreateProvisionedModelThroughput that must be refused; return its (code, message).
    An accepted create is deleted at once and waited gone, then fails the check."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    left = ctx.time_left()
    _delete_named_and_wait_gone(bedrock, name, _PT_DELETE_S if left is None else min(_PT_DELETE_S, left))
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and created {name!r} (deleted)")


# Inside the 900 s bedrock cleanup budget.
_PT_DELETE_S = 840.0


def _named(bedrock, name: str) -> list[str]:
    """ARNs of the provisioned throughputs named exactly `name`, over every listing page."""
    arns = []
    kwargs = {"nameContains": name}
    while True:
        page = bedrock.list_provisioned_model_throughputs(**kwargs)
        arns += [s["provisionedModelArn"] for s in page.get("provisionedModelSummaries", [])
                 if s.get("provisionedModelName") == name]
        token = page.get("nextToken")
        if not token:
            return arns
        kwargs["nextToken"] = token


def _delete_named_and_wait_gone(bedrock, name: str, timeout_s: float) -> None:
    """Delete every throughput named `name` and poll every 2 s until none is listed;
    ConflictException (still creating or updating) is retried, anything else, or the deadline
    passing, raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        arns = _named(bedrock, name)
        if not arns:
            return
        for arn in arns:
            try:
                bedrock.delete_provisioned_model_throughput(provisionedModelId=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"provisioned throughput {name!r} still listed at the delete deadline: {arns!r}")
        time.sleep(2)


def _first_provisionable_model_arn(bedrock) -> str:
    resp = bedrock.list_foundation_models(byInferenceType="PROVISIONED")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    ]
    if not summaries:
        raise AssertionError(
            "no ACTIVE foundation model in this account/region supports the PROVISIONED "
            "inference type that CreateProvisionedModelThroughput validates against"
        )
    return summaries[0]["modelArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
