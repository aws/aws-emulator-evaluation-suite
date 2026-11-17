"""create-secret-kms-key-id-forms-preserved-and-unknown-alias-refused."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-secret-kms-key-id-forms-preserved-and-unknown-alias-refused"
GROUP = "representation"
SERVICES = ["secretsmanager"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _expect_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
    "plane:data",
    "dp:api",
)
def run(ctx) -> None:
    """CreateSecret echoes a KmsKeyId exactly in the form given -- bare key id, alias, or key
    ARN -- and GetSecretValue decrypts each; an unknown alias is refused and creates nothing.
    """
    sm = ctx.client("secretsmanager")
    kms = ctx.client("kms")

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-smkey-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(
        _teardown(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7), "NotFoundException")
    )

    alias_name = "alias/" + ctx.unique_name("sim2real-behav-smalias-")
    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    ctx.on_cleanup(_teardown(lambda: kms.delete_alias(AliasName=alias_name), "NotFoundException"))

    forms = [
        ("bare", key_id, "kms-key-id-form-bare-value"),
        ("alias", alias_name, "kms-key-id-form-alias-value"),
        ("arn", key_arn, "kms-key-id-form-arn-value"),
    ]
    for label, reference, value in forms:
        name = ctx.unique_name(f"sim2real-behav-smform-{label}-")
        sm.create_secret(Name=name, SecretString=value, KmsKeyId=reference)
        ctx.on_cleanup(
            _teardown(
                lambda n=name: sm.delete_secret(SecretId=n, ForceDeleteWithoutRecovery=True),
                "ResourceNotFoundException",
            )
        )

        described = sm.describe_secret(SecretId=name)
        assert described.get("KmsKeyId") == reference, (
            f"expected DescribeSecret to echo the {label} KmsKeyId {reference!r} exactly as given, "
            f"got {described.get('KmsKeyId')!r}"
        )
        fetched = sm.get_secret_value(SecretId=name)["SecretString"]
        assert fetched == value, (
            f"expected GetSecretValue on the {label}-KmsKeyId secret to return {value!r}, got {fetched!r}"
        )

    bad_alias = "alias/" + ctx.unique_name("sim2real-behav-smmissing-")
    bad_alias_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:{bad_alias}"
    bad_name = ctx.unique_name("sim2real-behav-smbadalias-")
    code, message = _expect_error(
        lambda: sm.create_secret(Name=bad_name, SecretString="unused", KmsKeyId=bad_alias)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    # KMS proxies this refusal through its own NotFoundException, which stamps its own per-request
    # Request ID into the message; the fixed frame around it is pinned instead.
    prefix = (
        f"The operation failed because of an invalid KMS key: Alias {bad_alias_arn} is not found. "
        "(Service: AWSKMS; Status Code: 400; Error Code: NotFoundException; Request ID: "
    )
    suffix = "; Proxy: null)"
    assert message is not None and message.startswith(prefix) and message.endswith(suffix), (
        f"expected a message framed by {prefix!r} ... {suffix!r}, got {message!r}"
    )

    not_found_code, not_found_message = _expect_error(lambda: sm.describe_secret(SecretId=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code!r}"
    )
    assert not_found_message == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message: {not_found_message!r}"
    )

    # Positive control beside the refusal: the same real alias still resolves normally.
    control_name = ctx.unique_name("sim2real-behav-smaliascontrol-")
    sm.create_secret(Name=control_name, SecretString="alias-control-value", KmsKeyId=alias_name)
    ctx.on_cleanup(
        _teardown(
            lambda: sm.delete_secret(SecretId=control_name, ForceDeleteWithoutRecovery=True),
            "ResourceNotFoundException",
        )
    )
    control_described = sm.describe_secret(SecretId=control_name)
    assert control_described.get("KmsKeyId") == alias_name, (
        f"expected the control secret to echo {alias_name!r}, got {control_described.get('KmsKeyId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
