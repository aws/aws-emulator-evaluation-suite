"""resource-policy-public-policy-blocked."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "resource-policy-public-policy-blocked"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy must reject a policy that would make the secret publicly accessible,
    while a scoped (non-public) policy on the same secret still attaches."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(
        sm,
        ctx,
        name=name,
        secret_string="value",
        Tags=[{"Key": "sim2real", "Value": "resource-policy-public-policy-blocked"}],
    )

    public_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                }
            ],
        }
    )

    code, message = _error_code(
        lambda: sm.put_resource_policy(
            SecretId=name, ResourcePolicy=public_policy, BlockPublicPolicy=True
        )
    )
    assert code == "PublicPolicyException", (
        f"a wildcard-principal policy with BlockPublicPolicy=True must be rejected, got {code}"
    )
    assert message == (
        "You can not attach a resource policy that grants Public access to your secret."
    ), f"unexpected refusal message: {message!r}"

    # the secret must not have accidentally kept a policy from the rejected call
    got = sm.get_resource_policy(SecretId=name)
    assert "ResourcePolicy" not in got, (
        f"rejected public policy must leave no resource policy attached, "
        f"got policy={got.get('ResourcePolicy')!r}"
    )

    # positive control: a scoped (non-public) policy on the same secret must still attach --
    # otherwise a target that rejects every PutResourcePolicy call would pass the assertions above too.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    sm.put_resource_policy(
        SecretId=name, ResourcePolicy=json.dumps(scoped_policy), BlockPublicPolicy=True
    )
    ctx.on_cleanup(lambda: sm.delete_resource_policy(SecretId=name))
    attached = sm.get_resource_policy(SecretId=name)
    assert json.loads(attached["ResourcePolicy"]) == scoped_policy, (
        f"a scoped (non-public) policy must attach and round-trip, got {attached.get('ResourcePolicy')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
