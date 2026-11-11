"""resource-policy-put-get-delete-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-get-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy -> GetResourcePolicy -> DeleteResourcePolicy -> GetResourcePolicy(404)."""
    redshift = ctx.client("redshift")
    serverless = ctx.client("redshift-serverless")
    sts = ctx.client("sts")

    ns_name = ctx.unique_name("sim2real-rp-ns-")
    ns = serverless.create_namespace(
        namespaceName=ns_name, tags=[{"key": "sim2real-behavioral", "value": "true"}]
    )["namespace"]
    ns_arn = ns["namespaceArn"]
    ctx.on_cleanup(lambda: serverless.delete_namespace(namespaceName=ns_name))

    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "S2rAllowOwnAccountInboundIntegration",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": ns_arn,
            }
        ],
    }

    put_resp = redshift.put_resource_policy(ResourceArn=ns_arn, Policy=json.dumps(policy))
    put_policy = json.loads(put_resp["ResourcePolicy"]["Policy"])
    assert put_policy["Statement"][0]["Sid"] == "S2rAllowOwnAccountInboundIntegration", (
        f"put response Sid mismatch: {put_policy['Statement'][0]['Sid']!r}"
    )

    get_resp = redshift.get_resource_policy(ResourceArn=ns_arn)
    get_policy = json.loads(get_resp["ResourcePolicy"]["Policy"])
    assert get_policy["Statement"][0]["Sid"] == "S2rAllowOwnAccountInboundIntegration", (
        f"get response Sid mismatch: {get_policy['Statement'][0]['Sid']!r}"
    )
    assert get_policy["Statement"][0]["Action"] == "redshift:CreateInboundIntegration", (
        f"get response Action mismatch: {get_policy['Statement'][0]['Action']!r}"
    )

    redshift.delete_resource_policy(ResourceArn=ns_arn)

    code, message = _error(lambda: redshift.get_resource_policy(ResourceArn=ns_arn))
    assert code == "ResourceNotFoundFault", f"expected ResourceNotFoundFault after delete, got {code!r}"
    expected_get = "The requested resource policy doesn\u2019t exist."
    assert message == expected_get, f"expected message {expected_get!r}, got {message!r}"

    # a mutation on the now-deleted policy must also fail, not silently no-op
    redelete_code, redelete_message = _error(
        lambda: redshift.delete_resource_policy(ResourceArn=ns_arn)
    )
    assert redelete_code == "ResourceNotFoundFault", (
        f"expected ResourceNotFoundFault on double delete, got {redelete_code!r}"
    )
    expected_delete = "The requested resource policy doesn\u2019t exist."
    assert redelete_message == expected_delete, (
        f"expected message {expected_delete!r}, got {redelete_message!r}"
    )

    # the namespace itself is unaffected by the policy delete: the identifier is reusable
    reput_resp = redshift.put_resource_policy(ResourceArn=ns_arn, Policy=json.dumps(policy))
    reput_policy = json.loads(reput_resp["ResourcePolicy"]["Policy"])
    assert reput_policy["Statement"][0]["Sid"] == "S2rAllowOwnAccountInboundIntegration", (
        f"re-put after delete Sid mismatch: {reput_policy['Statement'][0]['Sid']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, so a target that accepts a call real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
