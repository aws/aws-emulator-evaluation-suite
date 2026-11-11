"""get-flow-execution-nonexistent-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-flow-execution-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDataIntegrationFlowExecution for a never-created instance, flow and execution fails with
    AccessDeniedException and the exact message: authorization on the instance ARN is evaluated
    before any existence lookup."""
    sc = ctx.client("supplychain")
    bogus_instance_id = str(uuid.uuid4())
    bogus_flow_name = "sim2real-nonexistent-flow"
    bogus_execution_id = str(uuid.uuid4())

    code, message = _error(
        lambda: sc.get_data_integration_flow_execution(
            instanceId=bogus_instance_id, flowName=bogus_flow_name, executionId=bogus_execution_id
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = (
        f"Authorization Failed (Public). The instanceId {bogus_instance_id} does not exist, "
        f"or does not belong to the account {ctx.account}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
