"""describe-blue-green-deployments."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-blue-green-deployments"
GROUP = 'blue_green_deployments'
SERVICES = ['rds']

ERR_BLUE_GREEN_NOT_FOUND = "BlueGreenDeploymentNotFoundFault"


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"expected {ERR_BLUE_GREEN_NOT_FOUND}, but the call SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeBlueGreenDeployments without a filter returns a list, and filtering by an unknown
    identifier is rejected with BlueGreenDeploymentNotFoundFault rather than answering empty."""
    rds = ctx.client("rds")
    resp = rds.describe_blue_green_deployments()
    assert "BlueGreenDeployments" in resp, f"expected BlueGreenDeployments key, got {resp!r}"

    well_shaped_but_unknown = "bgd-" + uuid.uuid4().hex[:26].upper()
    code, message = _error_code(
        lambda: rds.describe_blue_green_deployments(
            BlueGreenDeploymentIdentifier=well_shaped_but_unknown
        )
    )
    assert code == ERR_BLUE_GREEN_NOT_FOUND, f"unexpected error code: {code}"
    # AWS names the identifier lower-cased in the message.
    assert message == f"Blue Green Deployment '{well_shaped_but_unknown.lower()}' doesn't exist.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
