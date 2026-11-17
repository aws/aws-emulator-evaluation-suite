"""activation-past-expiration-date-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activation-past-expiration-date-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_ssm_trust_role(ctx, iam, name_prefix):
    role_name = ctx.unique_name(name_prefix)[:64]
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ssm.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_POLICY_ARN)
    return role_name


def _retry_on_role_propagation(fn, timeout_s=45.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "")
            if "nonexistent role" in msg.lower():
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_err


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateActivation with an ExpirationDate already in the past is refused with
    ValidationException, while the same role with a future ExpirationDate succeeds."""
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    role_name = _create_ssm_trust_role(ctx, iam, "sim2real-behav-probe-role-")

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    past = datetime.now(timezone.utc) - timedelta(days=1)
    bad_description = ctx.unique_name("sim2real-behav-probe-activation-past-")

    def create_past():
        resp = ssm.create_activation(
            IamRole=role_name,
            Description=bad_description,
            RegistrationLimit=1,
            ExpirationDate=past,
        )
        # If it unexpectedly succeeds, track it so cleanup removes it.
        ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=resp["ActivationId"]))
        return resp

    code, message = _retry_validation_propagation(create_past)
    assert code == "ValidationException", (
        f"expected ValidationException for a past ExpirationDate, got {code!r}: {message!r}"
    )
    assert message == "expirationDate must be greater than now and lesser than 30 days.", (
        f"CreateActivation message: {message!r}"
    )

    activations_after_bad = ssm.describe_activations()["ActivationList"]
    assert all(a["Description"] != bad_description for a in activations_after_bad), (
        "a rejected CreateActivation must not have minted an activation"
    )

    future = datetime.now(timezone.utc) + timedelta(days=1)
    good_description = ctx.unique_name("sim2real-behav-probe-activation-future-")
    good_resp = _retry_on_role_propagation(
        lambda: ssm.create_activation(
            IamRole=role_name,
            Description=good_description,
            RegistrationLimit=1,
            ExpirationDate=future,
        )
    )
    good_id = good_resp["ActivationId"]
    ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=good_id))
    assert good_resp["ActivationCode"], "a future ExpirationDate must be accepted"

    activations_after_good = ssm.describe_activations()["ActivationList"]
    matching = next(a for a in activations_after_good if a["ActivationId"] == good_id)
    assert matching["Expired"] is False, (
        f"a freshly created, not-yet-expired activation reports Expired={matching['Expired']!r}"
    )


def _retry_validation_propagation(fn, timeout_s=45.0, interval_s=3.0):
    """IAM role-trust propagation to the SSM control plane is eventually consistent and can
    surface as ValidationException with a role-related message before the real assertion
    (a past ExpirationDate) is reached; retry only that transient shape."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _error(fn)
        if last[0] == "ValidationException" and "nonexistent role" in (last[1] or "").lower():
            time.sleep(interval_s)
            continue
        return last
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
