"""resource-policy-overwrite-replaces-prior-document."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-overwrite-replaces-prior-document"
GROUP = "data-plane"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second PutResourcePolicy call on the same resource fully replaces the previously stored
    policy document rather than merging statements into it."""
    redshift = ctx.client("redshift")
    namespace = _create_namespace(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    policy_v1 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "FirstStatement",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": namespace["arn"],
            }
        ],
    }
    redshift.put_resource_policy(ResourceArn=namespace["arn"], Policy=json.dumps(policy_v1))
    ctx.on_cleanup(lambda: _delete_policy_quiet(redshift, namespace["arn"]))

    policy_v2 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SecondStatement",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:GetResourcePolicy",
                "Resource": namespace["arn"],
            }
        ],
    }
    put_resp = redshift.put_resource_policy(ResourceArn=namespace["arn"], Policy=json.dumps(policy_v2))
    stored = json.loads(put_resp["ResourcePolicy"]["Policy"])
    assert stored == policy_v2, f"PutResourcePolicy response did not echo the second document: expected={policy_v2} actual={stored}"
    assert stored != policy_v1, f"PutResourcePolicy response still matches the first document: {stored}"

    # Read back independently to confirm the replacement persisted server-side.
    get_resp = redshift.get_resource_policy(ResourceArn=namespace["arn"])
    fetched = json.loads(get_resp["ResourcePolicy"]["Policy"])
    assert fetched == policy_v2, f"GetResourcePolicy did not reflect the second document: expected={policy_v2} actual={fetched}"
    # A merge would have produced two statements (FirstStatement + SecondStatement); a
    # replace produces exactly one.
    assert len(fetched["Statement"]) == 1, (
        f"expected exactly 1 statement after overwrite (a merge would produce 2), got "
        f"{len(fetched['Statement'])}: {fetched['Statement']}"
    )
    assert fetched["Statement"][0]["Sid"] == "SecondStatement", (
        f"expected the surviving statement to be the second document's, got Sid="
        f"{fetched['Statement'][0]['Sid']!r}"
    )


def _create_namespace(ctx) -> dict:
    """Create a Redshift Serverless namespace: real AWS rejects PutResourcePolicy on a
    `cluster:` ARN outright (InvalidParameterValue: "Resource type cluster isn't supported for
    the resource policy"), so a namespace ARN is the resource type this operation actually
    supports."""
    serverless = ctx.client("redshift-serverless")
    ns_name = ctx.unique_name("sim2real-rp-ns-").lower()
    ns = serverless.create_namespace(
        namespaceName=ns_name,
        tags=[{"key": "sim2real-behavioral", "value": "true"}],
    )["namespace"]
    ctx.on_cleanup(lambda: serverless.delete_namespace(namespaceName=ns_name))
    return {"name": ns_name, "arn": ns["namespaceArn"]}


def _delete_policy_quiet(redshift, arn: str) -> None:
    try:
        redshift.delete_resource_policy(ResourceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
