"""get-domain-permissions-policy-unset-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-domain-permissions-policy-unset-not-found"
GROUP = "error-semantics"
SERVICES = ["codeartifact"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDomainPermissionsPolicy on a domain that never had a policy attached returns
    ResourceNotFoundException, distinct from an empty policy document."""
    ca = ctx.client("codeartifact")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    domain = (ctx.unique_name("sim2real-ca-") + "0").lower()

    created = ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])["domain"]
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))

    expected = ("ResourceNotFoundException", f"No policy found for (domain): ({domain})")
    refusal = _error(lambda: ca.get_domain_permissions_policy(domain=domain))
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    # Positive control: after attaching a policy, GetDomainPermissionsPolicy returns it.
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "codeartifact:DescribeDomain",
            "Resource": created["arn"],
        }],
    }
    ca.put_domain_permissions_policy(domain=domain, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: ca.delete_domain_permissions_policy(domain=domain))

    fetched = ca.get_domain_permissions_policy(domain=domain)["policy"]
    assert json.loads(fetched["document"]) == policy_doc, (
        f"expected {policy_doc}, got {fetched['document']}"
    )

    # Round trip: deleting the policy restores the original not-found state, not a
    # crash or a resurrected/empty-but-present policy.
    ca.delete_domain_permissions_policy(domain=domain)
    after_delete = _error(lambda: ca.get_domain_permissions_policy(domain=domain))
    assert after_delete == expected, (
        f"expected {expected!r} after delete, got {after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
