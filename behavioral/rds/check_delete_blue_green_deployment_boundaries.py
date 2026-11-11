"""delete-blue-green-deployment-boundaries."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-blue-green-deployment-boundaries"
GROUP = 'blue_green_deployments'
SERVICES = ['rds']

ERR_INVALID_PARAMETER_VALUE = "InvalidParameterValue"
ERR_BLUE_GREEN_NOT_FOUND = "BlueGreenDeploymentNotFoundFault"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBlueGreenDeployment checks the identifier's shape before existence: an arbitrary
    string rejects with InvalidParameterValue, a well-shaped unknown id with
    BlueGreenDeploymentNotFoundFault."""
    rds = ctx.client("rds")
    bogus_shape = ctx.unique_name("sim2real-behav-bgd-missing-")
    code, message = _error_code(
        lambda: rds.delete_blue_green_deployment(BlueGreenDeploymentIdentifier=bogus_shape)
    )
    assert code == ERR_INVALID_PARAMETER_VALUE, f"unexpected error code: {code}"
    assert message == f"Invalid blue-green deployment identifier: {bogus_shape}", message

    well_shaped_but_unknown = "bgd-" + uuid.uuid4().hex[:26].upper()
    code2, message2 = _error_code(
        lambda: rds.delete_blue_green_deployment(
            BlueGreenDeploymentIdentifier=well_shaped_but_unknown
        )
    )
    assert code2 == ERR_BLUE_GREEN_NOT_FOUND, f"unexpected error code: {code2}"
    assert message2 == f"Blue Green Deployment '{well_shaped_but_unknown}' doesn't exist.", message2


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
