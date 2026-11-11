"""op-contract-getAccountAuthorizationDetails."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-getAccountAuthorizationDetails"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccountAuthorizationDetails lists a real user with its inline policy document exactly as
    submitted and its attached managed policy, and MaxItems=1 bounds each page to at most one user."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-gaad-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    inline_policy_name = "sim2real-inline"
    inline_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }
    iam.put_user_policy(UserName=user_name, PolicyName=inline_policy_name, PolicyDocument=json.dumps(inline_doc))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=inline_policy_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    iam.attach_user_policy(UserName=user_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_user_policy(UserName=user_name, PolicyArn=managed_policy_arn))

    found = None
    marker = None
    while found is None:
        kwargs = {"Filter": ["User"], "MaxItems": 1}
        if marker:
            kwargs["Marker"] = marker
        page = iam.get_account_authorization_details(**kwargs)
        assert len(page["UserDetailList"]) <= 1, (
            f"MaxItems=1 must bound the page server-side, got {len(page['UserDetailList'])} users"
        )
        found = next((u for u in page["UserDetailList"] if u["UserName"] == user_name), None)
        if not page.get("IsTruncated") or found is not None:
            break
        marker = page["Marker"]

    assert found is not None, f"user {user_name!r} missing from GetAccountAuthorizationDetails"
    inline_policies = {p["PolicyName"]: p["PolicyDocument"] for p in found.get("UserPolicyList", [])}
    assert inline_policy_name in inline_policies, f"inline policy missing: {sorted(inline_policies)}"
    got_doc = inline_policies[inline_policy_name]
    assert got_doc == inline_doc, f"inline policy document mismatch: {got_doc} != {inline_doc}"
    attached_arns = {p["PolicyArn"] for p in found.get("AttachedManagedPolicies", [])}
    assert managed_policy_arn in attached_arns, f"attached policy missing: {attached_arns}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
