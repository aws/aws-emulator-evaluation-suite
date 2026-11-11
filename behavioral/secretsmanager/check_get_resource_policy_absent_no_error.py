"""get-resource-policy-absent-no-error."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

def _account_id_from_arn(arn):
    return arn.split(":")[4]

def _own_root_principal(arn):
    return f"arn:aws:iam::{_account_id_from_arn(arn)}:root"

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

CHECK = "get-resource-policy-absent-no-error"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a secret with no attached policy succeeds with no ResourcePolicy field;
    a control secret with a policy attached must report it, so an always-empty answer fails."""
    sm = ctx.client("secretsmanager")

    control_name = ctx.unique_name("sim2real-behav-secret-control-")
    control_resp = _create_secret(sm, ctx, name=control_name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": _own_root_principal(control_resp["ARN"])},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": control_resp["ARN"],
            }
        ],
    }
    sm.put_resource_policy(SecretId=control_name, ResourcePolicy=json.dumps(policy))
    control_got = sm.get_resource_policy(SecretId=control_name)
    assert control_got.get("ResourcePolicy"), (
        f"expected control secret {control_name} to report the policy just attached, got {control_got!r}"
    )

    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name)

    resp = sm.get_resource_policy(SecretId=name)
    assert not resp.get("ResourcePolicy"), (
        f"expected no ResourcePolicy field for {name}, which never had a policy attached, got {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
