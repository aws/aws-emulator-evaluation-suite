"""get-access-key-info-persists-after-key-deletion."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-access-key-info-persists-after-key-deletion"
GROUP = 'credential-issuance'
SERVICES = ['sts']


@tags("axis:happy-path", "cap:unclassified", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAccessKeyInfo is a stateless prefix-decode, not a live lookup: it still resolves the account after the key is deleted."""

    sts = ctx.client("sts")

    def _account_id():
        return sts.get_caller_identity()["Account"]

    def _tags_kv():
        return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

    def _create_user():
        user_name = ctx.unique_name("sim2real-behav-sts-user-")
        iam.create_user(UserName=user_name, Tags=_tags_kv())

        def _drop_user(user_name=user_name):
            try:
                for k in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
                    try:
                        iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "NoSuchEntity":
                            raise
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            try:
                iam.delete_user(UserName=user_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_drop_user)
        key = iam.create_access_key(UserName=user_name)["AccessKey"]
        creds = {"AccessKeyId": key["AccessKeyId"], "SecretAccessKey": key["SecretAccessKey"]}
        user_arn = iam.get_user(UserName=user_name)["User"]["Arn"]
        return user_name, user_arn, creds

    iam = ctx.client("iam")

    account = _account_id()
    user_name, _user_arn, user_creds = _create_user()
    access_key_id = user_creds["AccessKeyId"]

    iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)

    remaining = [
        k["AccessKeyId"] for k in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
    ]
    assert access_key_id not in remaining, (access_key_id, remaining)

    resp = sts.get_access_key_info(AccessKeyId=access_key_id)
    assert resp["Account"] == account, resp

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
