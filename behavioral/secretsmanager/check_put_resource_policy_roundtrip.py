"""put-resource-policy-roundtrip."""
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
    params = {"Name": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "put-resource-policy-roundtrip"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy attaches a resource policy retrievable via GetResourcePolicy."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    resp = _create_secret(sm, ctx, name=name)
    arn = resp["ARN"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": _own_root_principal(arn)},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": arn,
            }
        ],
    }

    sm.put_resource_policy(SecretId=name, ResourcePolicy=json.dumps(policy))

    got = sm.get_resource_policy(SecretId=name)
    assert "ResourcePolicy" in got, f"expected a ResourcePolicy field after PutResourcePolicy, got keys={sorted(got.keys())}"
    returned_statement = json.loads(got["ResourcePolicy"])["Statement"][0]
    assert returned_statement == policy["Statement"][0], (
        f"resource policy did not round-trip: expected {policy['Statement'][0]!r}, got {returned_statement!r}"
    )

    sm.delete_resource_policy(SecretId=name)
    got2 = sm.get_resource_policy(SecretId=name)
    assert not got2.get("ResourcePolicy"), f"expected no ResourcePolicy after DeleteResourcePolicy, got {got2.get('ResourcePolicy')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
