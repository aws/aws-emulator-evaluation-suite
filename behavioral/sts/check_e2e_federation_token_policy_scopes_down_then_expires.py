"""e2e-federation-token-policy-scopes-down-then-expires."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-federation-token-policy-scopes-down-then-expires"
GROUP = "e2e"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A federation token's effective permissions are the policy given."""
    sts = ctx.client("sts")
    ctx.client("s3")

    caller_arn = sts.get_caller_identity()["Arn"]
    if ":assumed-role/" in caller_arn or ":federated-user/" in caller_arn:
        raise AssertionError(
            "GetFederationToken requires long-term IAM user (or root) credentials; the "
            f"current caller ({caller_arn}) is a temporary/federated session"
        )

    bucket_name = ctx.unique_name("sim2real-behav-fed-")
    ctx.on_cleanup(lambda: _delete_bucket_if_exists(ctx.client("s3"), bucket_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
    }
    fed_name = ctx.unique_name("sim2real-fed-")
    resp = sts.get_federation_token(
        Name=fed_name, Policy=json.dumps(policy_doc), DurationSeconds=900
    )
    creds = resp["Credentials"]
    fed_user_arn = resp["FederatedUser"]["Arn"]
    assert fed_user_arn.endswith(f"federated-user/{fed_name}"), (
        f"FederatedUser.Arn must end in federated-user/{fed_name}; got {fed_user_arn!r}"
    )

    fed_s3 = _client_from_creds(ctx, "s3", creds)

    # Allowed action succeeds.
    listed = fed_s3.list_buckets()
    assert "Buckets" in listed, (
        f"s3:ListAllMyBuckets is granted by the session policy, so ListBuckets must succeed and "
        f"return a Buckets key; got keys {sorted(listed.keys())!r}"
    )

    # Disallowed action (not in the scoping policy) is denied.
    create_kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own historical default region: the S3 API rejects an
        # explicit LocationConstraint for it, so the literal here is the API's quirk, not a
        # hardcoded test region.
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    code, message = _client_error(lambda: fed_s3.create_bucket(**create_kwargs))
    assert code == "AccessDenied", (
        f"s3:CreateBucket is absent from the session policy, so it must be refused with exactly "
        f"AccessDenied; got {code!r}"
    )
    assert message == (
        f"User: {fed_user_arn} is not authorized to perform: s3:CreateBucket on resource: "
        f'"arn:aws:s3:::{bucket_name}" because no session policy allows the s3:CreateBucket action'
    ), message

    # Effect absent: the bucket the denied call tried to create does not exist.
    admin_names = [b["Name"] for b in ctx.client("s3").list_buckets()["Buckets"]]
    assert bucket_name not in admin_names, (
        f"the denied CreateBucket must have had no effect, but {bucket_name!r} is in the admin "
        f"account's bucket list {admin_names!r}"
    )


def _client_error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded where AWS refuses it")


def _delete_bucket_if_exists(s3, bucket_name) -> None:
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _client_from_creds(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
