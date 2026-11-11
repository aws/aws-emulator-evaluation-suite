"""create-activation-nonexistent-role-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-activation-nonexistent-role-fails"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateActivation with a role trusted by ssm.amazonaws.com returns an ActivationCode, while a
    nonexistent IamRole fails with ValidationException and the exact nonexistent-role message and
    creates no activation."""

    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    role_name = _create_ssm_trust_role(ctx, iam, "sim2real-behav-probe-role-")

    good_description = ctx.unique_name("sim2real-behav-probe-activation-good-")
    good_resp = _retry_on_role_propagation(
        lambda: ssm.create_activation(
            IamRole=role_name,
            Description=good_description,
            RegistrationLimit=1,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    good_id = good_resp["ActivationId"]
    ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=good_id))
    assert good_resp["ActivationCode"], "a role with a correct trust policy must be accepted"
    assert _find_activation(ssm, good_id) is not None, (
        "the accepted activation must be visible through DescribeActivations"
    )

    bad_description = ctx.unique_name("sim2real-behav-probe-activation-bad-")
    bogus_role = ctx.unique_name("sim2real-behav-probe-nonexistent-role-")

    def create_bad():
        resp = ssm.create_activation(
            IamRole=bogus_role,
            Description=bad_description,
            RegistrationLimit=1,
        )
        # If it unexpectedly succeeds, track it so cleanup removes it.
        ctx.on_cleanup(lambda: ssm.delete_activation(ActivationId=resp["ActivationId"]))
        return resp

    code, message = _error(create_bad)
    assert code == "ValidationException", (
        f"expected ValidationException for a nonexistent IamRole, got {code!r}"
    )
    assert message == (
        "Nonexistent role or missing ssm service principal in trust policy: "
        f"arn:aws:iam::{ctx.account}:role/{bogus_role}"
    ), f"CreateActivation message: {message!r}"

    activations_after = ssm.describe_activations()["ActivationList"]
    assert all(a["Description"] != bad_description for a in activations_after), (
        "a rejected CreateActivation must not have minted an activation"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to raise, but it succeeded")


def _find_activation(ssm, activation_id):
    next_token = None
    for _ in range(50):
        kwargs = {
            "Filters": [{"FilterKey": "ActivationIds", "FilterValues": [activation_id]}]
        }
        if next_token:
            kwargs["NextToken"] = next_token
        page = ssm.describe_activations(**kwargs)
        for item in page.get("ActivationList", []):
            if item["ActivationId"] == activation_id:
                return item
        next_token = page.get("NextToken")
        if not next_token:
            break
    return None


def _create_ssm_trust_role(ctx, iam, name_prefix):
    import json

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
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_name


def _safe_delete_role(iam, role_name):
    from botocore.exceptions import ClientError

    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_on_role_propagation(fn, timeout_s=45.0, interval_s=3.0):
    import time

    from botocore.exceptions import ClientError

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
