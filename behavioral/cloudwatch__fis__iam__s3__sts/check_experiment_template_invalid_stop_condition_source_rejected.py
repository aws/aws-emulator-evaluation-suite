"""experiment-template-invalid-stop-condition-source-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-template-invalid-stop-condition-source-rejected"
GROUP = "experiment-template"
SERVICES = ["fis", "iam"]

_INVALID_SOURCE = (
    "ValidationException",
    "Invalid source for Stop Condition: [sim2real-not-a-stop-condition-source].",
)

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "fis.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_template(fis, template_id: str) -> None:
    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _base_kwargs(role_arn: str, client_token: str, description: str, source: str) -> dict:
    return dict(
        clientToken=client_token,
        description=description,
        roleArn=role_arn,
        stopConditions=[{"source": source}],
        targets={},
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message) -> None:
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExperimentTemplate rejects a stop condition source that is neither "none" nor
    "aws:cloudwatch:alarm", and a template with the valid "none" source is still created.
    """
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_name = ctx.unique_name("sim2real-fis-stopcond-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    control_token = ctx.unique_name("sim2real-fis-stopcond-control-")
    last_exc = None
    control = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            control = fis.create_experiment_template(
                **_base_kwargs(role_arn, control_token, "sim2real stop condition control", "none")
            )["experimentTemplate"]
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"]["Message"]
            if code == "ResourceNotFoundException" or (
                code == "ValidationException" and "assume role" in msg.lower()
            ):
                last_exc = exc
                time.sleep(3.0)
                continue
            raise
    if control is None:
        raise last_exc
    control_id = control["id"]
    ctx.on_cleanup(lambda: _delete_template(fis, control_id))

    got_control = fis.get_experiment_template(id=control_id)["experimentTemplate"]
    assert got_control["stopConditions"] == [{"source": "none"}], (
        f"the control template's stop condition was {got_control['stopConditions']!r}, "
        "expected [{'source': 'none'}]"
    )

    invalid_token = ctx.unique_name("sim2real-fis-stopcond-invalid-")
    expect_error(
        lambda: fis.create_experiment_template(
            **_base_kwargs(
                role_arn, invalid_token, "sim2real stop condition invalid source",
                "sim2real-not-a-stop-condition-source",
            )
        ),
        *_INVALID_SOURCE,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
