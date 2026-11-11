"""put-resource-policy-malformed-document-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-document-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a syntactically malformed policy document with
    MalformedResourcePolicyDocumentException and attaches no policy, whereas a
    well-formed policy on the same resource (positive control) succeeds."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    param_name = ctx.unique_name("sim2real-respolicy-malformed-")
    ssm.put_parameter(
        Name=param_name, Value="v1", Type="String", Tier="Advanced",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))
    resource_arn = ssm.get_parameter(Name=param_name)["Parameter"]["ARN"]

    code, message = _client_error(
        lambda: ssm.put_resource_policy(ResourceArn=resource_arn, Policy="{not valid json")
    )
    assert code == "MalformedResourcePolicyDocumentException", code
    assert message == "Policy is malformed and cannot be parsed", message

    # Effect-absent: the rejected call attached no policy.
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    assert policies == [], policies

    # A well-formed policy on the same resource succeeds.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realShare",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "ssm:GetParameter",
                "Resource": resource_arn,
            }
        ],
    }
    put_resp = ssm.put_resource_policy(ResourceArn=resource_arn, Policy=json.dumps(policy_doc))
    policy_id = put_resp["PolicyId"]
    ctx.on_cleanup(lambda: _delete_policy_if_present(ssm, resource_arn, policy_id))

    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    assert any(p["PolicyId"] == policy_id for p in policies), policies


def _delete_policy_if_present(ssm, resource_arn: str, policy_id: str) -> None:
    policies = ssm.get_resource_policies(ResourceArn=resource_arn)["Policies"]
    match = next((p for p in policies if p["PolicyId"] == policy_id), None)
    if match is not None:
        ssm.delete_resource_policy(
            ResourceArn=resource_arn, PolicyId=policy_id, PolicyHash=match["PolicyHash"]
        )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
