"""get-access-key-info-round-trip-preserves-account-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-access-key-info-round-trip-preserves-account-id"
GROUP = "representation"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The account id embedded in a freshly minted access key id is byte-identical to the
    account id GetAccessKeyInfo decodes back out of that same access key id."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    expected_account = sts.get_caller_identity()["Account"]

    user_name = ctx.unique_name("sim2real-behav-gaki-")
    iam.create_user(
        UserName=user_name,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = access_key["AccessKeyId"]
    ctx.on_cleanup(
        lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
    )

    resolved = sts.get_access_key_info(AccessKeyId=access_key_id)
    assert resolved["Account"] == expected_account, (resolved, expected_account)
    # sanity: the field really is a plain decimal account id, not e.g. an ARN or UUID
    assert resolved["Account"].isdigit() and len(resolved["Account"]) == 12, resolved


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
