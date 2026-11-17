"""put-object-acl-canned-and-policy-together-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-acl-canned-and-policy-together-rejected"
GROUP = "error-semantics"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectAcl rejects a canned ACL combined with an explicit AccessControlPolicy body,
    leaving the object's prior ACL grants unchanged."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    key = "object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"acl-conflict-body")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    owner = s3.get_object_acl(Bucket=bucket, Key=key)["Owner"]

    # positive control: AccessControlPolicy alone is accepted and replaces the grant set
    two_grants = {
        "Owner": owner,
        "Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"},
            {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "READ_ACP"},
        ],
    }
    s3.put_object_acl(Bucket=bucket, Key=key, AccessControlPolicy=two_grants)
    control = s3.get_object_acl(Bucket=bucket, Key=key)
    control_perms = sorted(g["Permission"] for g in control["Grants"])
    assert control_perms == ["FULL_CONTROL", "READ_ACP"], (
        f"expected the AccessControlPolicy-only put to set [FULL_CONTROL, READ_ACP], got {control_perms!r}"
    )

    code, message = _client_error(
        lambda: s3.put_object_acl(
            Bucket=bucket,
            Key=key,
            ACL="private",
            AccessControlPolicy={
                "Owner": owner,
                "Grants": [
                    {"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"}
                ],
            },
        )
    )
    assert code == "UnexpectedContent", f"expected UnexpectedContent, got {code!r}"
    assert message == "This request does not support content", f"unexpected message {message!r}"

    after = s3.get_object_acl(Bucket=bucket, Key=key)
    after_perms = sorted(g["Permission"] for g in after["Grants"])
    assert after_perms == ["FULL_CONTROL", "READ_ACP"], (
        f"the rejected put must leave the prior two-grant ACL intact, got {after_perms!r}"
    )


def _client_error(fn):
    """The botocore (Error.Code, Error.Message) of fn(); RAISES if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-aclconf-")
    kwargs = {"Bucket": name, "ObjectOwnership": "ObjectWriter"}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
