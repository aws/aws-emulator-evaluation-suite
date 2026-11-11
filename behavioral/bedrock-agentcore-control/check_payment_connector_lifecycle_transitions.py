"""payment-connector-lifecycle-transitions."""
from __future__ import annotations

import base64
import json
import os
import time

from behavioral_harness import tags

CHECK = "payment-connector-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


def _b64_secret(nbytes: int = 32) -> str:
    """A base64-encoded random secret matching the generic base64-charset shape
    StripePrivy's appSecret accepts at the SDK/parameter level."""
    return base64.b64encode(os.urandom(nbytes)).decode("ascii")


def _b64_ec_p256_key() -> str:
    """A base64-encoded PKCS8 DER EC P-256 private key, matching the format
    CreatePaymentCredentialProvider validates authorizationPrivateKey against."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(der).decode("ascii")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A StripePrivy payment connector on a READY manager reaches READY, returns to READY after an update with a
    non-decreasing lastUpdatedAt, and after delete Get and Update answer ResourceNotFoundException with their exact
    messages."""
    client = ctx.client("bedrock-agentcore-control")
    role_arn = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3pcn")
    manager_name = _payments_name(ctx, "sim2realpcm")
    cred_name = _alnum_name(ctx, "sim2reals3pcnc")
    app_id = _alnum_name(ctx, "sim2realspapp")
    authorization_id = _alnum_name(ctx, "sim2realspauth")

    cred = client.create_payment_credential_provider(
        name=cred_name,
        credentialProviderVendor="StripePrivy",
        providerConfigurationInput={
            "stripePrivyConfiguration": {
                "appId": app_id,
                "appSecret": _b64_secret(),
                "authorizationPrivateKey": _b64_ec_p256_key(),
                "authorizationId": authorization_id,
            }
        },
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client.delete_payment_credential_provider, name=cred_name))
    cred_arn = cred["credentialProviderArn"]

    manager = client.create_payment_manager(
        name=manager_name, authorizerType="AWS_IAM", roleArn=role_arn, tags={"sim2real": CHECK}
    )
    manager_id = manager["paymentManagerId"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client.delete_payment_manager, paymentManagerId=manager_id))
    _poll_until(
        lambda: client.get_payment_manager(paymentManagerId=manager_id),
        lambda r: r["status"] == "READY",
        timeout_s=180.0,
    )

    connector_name = _payments_name(ctx, "sim2realconn")
    connector = client.create_payment_connector(
        paymentManagerId=manager_id,
        name=connector_name,
        type="StripePrivy",
        credentialProviderConfigurations=[{"stripePrivy": {"credentialProviderArn": cred_arn}}],
    )

    connector_id = connector["paymentConnectorId"]
    ctx.on_cleanup(
        lambda: _delete_ignore_not_found(
            client.delete_payment_connector, paymentManagerId=manager_id, paymentConnectorId=connector_id
        )
    )
    assert connector["paymentManagerId"] == manager_id
    assert connector["type"] == "StripePrivy"

    settled = _poll_until(
        lambda: client.get_payment_connector(paymentManagerId=manager_id, paymentConnectorId=connector_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=180.0,
    )
    assert settled["status"] == "READY", f"expected connector to settle READY, got {settled['status']!r}"
    first_updated_at = settled["lastUpdatedAt"]

    updated = client.update_payment_connector(
        paymentManagerId=manager_id,
        paymentConnectorId=connector_id,
        type="StripePrivy",
        credentialProviderConfigurations=[{"stripePrivy": {"credentialProviderArn": cred_arn}}],
    )
    assert updated["paymentConnectorId"] == connector_id
    got_after_update = _poll_until(
        lambda: client.get_payment_connector(paymentManagerId=manager_id, paymentConnectorId=connector_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=180.0,
    )
    assert got_after_update["status"] == "READY", (
        f"expected connector to settle READY after update, got {got_after_update['status']!r}"
    )
    assert got_after_update["lastUpdatedAt"] >= first_updated_at

    client.delete_payment_connector(paymentManagerId=manager_id, paymentConnectorId=connector_id)

    final_code, final_message = _poll_gone(
        lambda: client.get_payment_connector(paymentManagerId=manager_id, paymentConnectorId=connector_id),
        timeout_s=180.0,
    )
    assert final_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {final_code!r}"
    expected_final = f"Payment connector not found: {connector_id}"
    assert final_message == expected_final, f"expected message {expected_final!r}, got {final_message!r}"

    # The dead id is unusable, not just absent from a read -- a mutation against it
    # must fail with the same specific not-found code.
    update_code, update_message = _error_detail(
        lambda: client.update_payment_connector(
            paymentManagerId=manager_id,
            paymentConnectorId=connector_id,
            type="StripePrivy",
            credentialProviderConfigurations=[{"stripePrivy": {"credentialProviderArn": cred_arn}}],
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a deleted connector, got {update_code!r}"
    )
    expected_update = f"Payment connector not found: connectorId={connector_id}, managerId={manager_id}"
    assert update_message == expected_update, f"expected message {expected_update!r}, got {update_message!r}"


def _payments_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    alnum = "".join(ch for ch in raw if ch.isalnum())
    return alnum[:48]


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch in "-_")


def _create_role(ctx, principal: str, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-payments-permissions",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "bedrock-agentcore:*", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_ignore(iam, role_name, "sim2real-payments-permissions"))
    return arn


def _delete_role_policy_ignore(iam, role_name: str, policy_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_gone(read, timeout_s=180.0, interval_s=3.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _delete_ignore_not_found(delete_fn, **kwargs) -> None:
    from botocore.exceptions import ClientError

    try:
        delete_fn(**kwargs)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
