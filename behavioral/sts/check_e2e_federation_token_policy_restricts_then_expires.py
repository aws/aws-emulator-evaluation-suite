"""e2e-federation-token-policy-restricts-then-expires."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "e2e-federation-token-policy-restricts-then-expires"
GROUP = "state-machine"
SERVICES = ["sts"]


@tags("axis:rejection", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """A federation session scoped to s3:ListAllMyBuckets lists buckets and reports its Arn, but
    IAM rejects it with InvalidClientTokenId; Expiration is ~900 s out and DurationSeconds=899
    fails ValidationError with the exact minimum-900 message.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-feduser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    iam.put_user_policy(
        UserName=user_name,
        PolicyName="allow-get-federation-token",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:GetFederationToken", "Resource": "*"},
                    # Session permissions are the intersection of this policy and the
                    # session Policy, so the S3 action must be granted here too.
                    {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_user_policy(
                UserName=user_name, PolicyName="allow-get-federation-token"
            )
        )
    )

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    key_id = key["AccessKeyId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key_id)
        )
    )
    long_term_creds = {"AccessKeyId": key_id, "SecretAccessKey": key["SecretAccessKey"]}
    long_term_client = _client_with_creds(ctx, "sts", long_term_creds)
    _retry_until_success(
        lambda: long_term_client.get_caller_identity(), timeout_s=30.0, interval_s=2.0
    )

    fed_name = ctx.unique_name("s2rfed-")[:32]
    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}
        ],
    }

    def _get_fed_token() -> dict:
        return long_term_client.get_federation_token(
            Name=fed_name,
            Policy=json.dumps(scoped_policy),
            DurationSeconds=900,
        )

    # Session permissions are snapshotted at mint time, so a token minted before the identity
    # policy propagated never gains it; re-mint on each retry.
    state: dict[str, Any] = {}

    def _mint_and_probe() -> bool:
        fed_result = _get_fed_token()
        creds = fed_result["Credentials"]
        s3_fed = _client_with_creds(ctx, "s3", creds)
        s3_fed.list_buckets()  # raises if the intersection doesn't yet grant this
        state["fed_result"] = fed_result
        state["creds"] = creds
        return True

    _retry_until_success(_mint_and_probe, timeout_s=60.0, interval_s=3.0)
    fed_result = state["fed_result"]
    creds = state["creds"]
    fed_arn = fed_result["FederatedUser"]["Arn"]

    sts_fed = _client_with_creds(ctx, "sts", creds)
    _client_with_creds(ctx, "s3", creds)

    assert sts_fed.get_caller_identity()["Arn"] == fed_arn

    # A token from a regional STS endpoint fails IAM (us-east-1) with SignatureDoesNotMatch
    # before authorization, so a us-east-1-scoped token is minted for the IAM probe.
    iam_probe_creds = _iam_probe_creds(ctx, long_term_creds, fed_name, scoped_policy)
    iam_fed = _client_with_creds(ctx, "iam", iam_probe_creds, region="us-east-1")
    # The federated-user credential type is rejected at the authentication layer
    # (InvalidClientTokenId), not via policy evaluation.
    denied_code, denied_message = _client_error(lambda: iam_fed.list_users())
    assert denied_code == "InvalidClientTokenId", f"unexpected code: {denied_code}"
    assert denied_message == "The security token included in the request is invalid", denied_message

    expiration: datetime.datetime = creds["Expiration"]
    now = datetime.datetime.now(datetime.timezone.utc)
    wait_s = (expiration - now).total_seconds()
    assert wait_s > 0
    # The 900 s minimum duration exceeds the check's time budget, so expiry is not waited out;
    # the Expiration offset and the floor are asserted instead.
    assert abs(wait_s - 900) < 30, f"unexpected Expiration offset: {wait_s}s"

    # botocore validates min=900 locally; disable client-side validation so 899 reaches STS.
    floor_probe_client = _client_with_creds(
        ctx, "sts", long_term_creds, validate_params=False
    )
    floor_code, floor_message = _client_error(
        lambda: floor_probe_client.get_federation_token(
            Name=ctx.unique_name("s2rfedfloor-")[:32],
            Policy=json.dumps(scoped_policy),
            DurationSeconds=899,
        )
    )
    assert floor_code == "ValidationError", f"unexpected code: {floor_code}"
    assert floor_message == (
        "1 validation error detected: Value '899' at 'durationSeconds' failed to satisfy "
        "constraint: Member must have value greater than or equal to 900"
    ), floor_message



def _ignore_no_such_entity(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded where AWS refuses it")


def _iam_probe_creds(ctx: Any, long_term_creds: dict, fed_name: str, scoped_policy: dict) -> dict:
    global_sts = ctx.client(
        "sts",
        region="us-east-1",
        endpoint_url=ctx.service_url("https://sts.amazonaws.com"),
        creds={
            "aws_access_key_id": long_term_creds["AccessKeyId"],
            "aws_secret_access_key": long_term_creds["SecretAccessKey"],
        },
    )
    return global_sts.get_federation_token(
        Name=fed_name, Policy=json.dumps(scoped_policy), DurationSeconds=900
    )["Credentials"]


def _client_with_creds(
    ctx: Any,
    service: str,
    creds: dict,
    *,
    validate_params: bool = True,
    region: str | None = None,
) -> Any:
    from botocore.config import Config

    # The signing region for a regionally-scoped STS session comes from ``region``;
    # ctx.client keeps the target's own endpoint for every service including IAM.
    return ctx.client(
        service,
        region=region,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        },
        config=None if validate_params else Config(parameter_validation=False),
    )


def _retry_until_success(
    fn: Callable[[], Any], *, timeout_s: float, interval_s: float
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


def _retry_until(
    fn: Callable[[], Any], *, predicate: Callable[[Any], bool], timeout_s: float, interval_s: float
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
