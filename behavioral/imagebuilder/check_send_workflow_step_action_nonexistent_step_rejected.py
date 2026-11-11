"""send-workflow-step-action-nonexistent-step-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-workflow-step-action-nonexistent-step-rejected"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendWorkflowStepAction against a stepExecutionId that was never created is rejected with InvalidParameterValueException."""
    ib = ctx.client("imagebuilder")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_step_id = f"step-{uuid.uuid4().hex}"
    bogus_image_name = ctx.unique_name("sim2real-ib-nonexistent-image-")
    bogus_image_arn = f"arn:aws:imagebuilder:{ctx.region}:{account_id}:image/{bogus_image_name}/1.0.0/1"

    code, message = _error(
        lambda: ib.send_workflow_step_action(
            stepExecutionId=bogus_step_id,
            imageBuildVersionArn=bogus_image_arn,
            action="RESUME",
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    expected = (
        "The value supplied for parameter 'stepExecutionId' is not valid. stepExecutionId must match pattern "
        "^step-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a sibling read-only workflow-step listing operation still works normally
    resp = ib.list_waiting_workflow_steps()
    assert "steps" in resp, f"expected a 'steps' key in ListWaitingWorkflowSteps response, got {resp!r}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected SendWorkflowStepAction to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
