"""op-contract-getAccessKeyLastUsed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-getAccessKeyLastUsed"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccessKeyLastUsed resolves the owning UserName of an unused key with
    N/A ServiceName and Region, and refuses a well-formed never-issued
    AccessKeyId with AccessDenied and its exact message."""
    iam = ctx.client("iam")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    user_name = ctx.unique_name("sim2real-behav-akl-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id))

    resp = iam.get_access_key_last_used(AccessKeyId=access_key_id)
    assert resp["UserName"] == user_name, f"expected UserName {user_name!r}, got {resp['UserName']!r}"
    last_used = resp["AccessKeyLastUsed"]
    # A key that has never made a request has no ServiceName/Region -- AWS
    # reports the sentinel "N/A" for both rather than fabricating a value.
    assert last_used.get("ServiceName", "N/A") == "N/A"
    assert last_used.get("Region", "N/A") == "N/A"

    # Well-formed (20 chars, satisfies the documented 16-128 char pattern) but
    # never issued by any account -- this must actually reach IAM rather than
    # being rejected client-side. IAM cannot resolve an owning user for an
    # unrecognized key and, rather than confirming its absence, refuses with
    # AccessDenied (not NoSuchEntity) so as not to leak whether the id exists.
    never_issued = "AKIA" + "Z" * 16
    code, message = _error(lambda: iam.get_access_key_last_used(AccessKeyId=never_issued))
    assert code == "AccessDenied", f"expected AccessDenied, got {code}"
    expected = (
        f"User: {caller_arn} is not authorized to perform iam:GetAccessKeyLastUsed "
        f"on resource: access key {never_issued}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
