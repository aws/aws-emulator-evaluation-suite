"""start-device-authorization-wrong-client-secret-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-device-authorization-wrong-client-secret-rejected"
GROUP = "authentication"
SERVICES = ["sso-oidc"]


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


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {sorted(result)!r}")


def _start_url(ctx) -> str:
    """The start URL of an ACTIVE IAM Identity Center instance in this account.

    The instance is an account singleton: read the prior state first, adopt an existing
    instance, and only when there is none create one and register its deletion, so the account
    ends in exactly the state it started in.
    """
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances()["Instances"]
    if not instances:
        arn = sso_admin.create_instance(Name=ctx.unique_name("sim2real-behav-idc-"))["InstanceArn"]
        ctx.on_cleanup(_teardown(lambda: sso_admin.delete_instance(InstanceArn=arn),
                                 "ResourceNotFoundException"))
    deadline = time.monotonic() + 300
    while True:
        instances = sso_admin.list_instances()["Instances"]
        active = [i for i in instances if i.get("Status") == "ACTIVE" and i.get("IdentityStoreId")]
        if active:
            return f"https://{active[0]['IdentityStoreId']}.awsapps.com/start"
        assert time.monotonic() < deadline, (
            f"no IAM Identity Center instance became ACTIVE; statuses {[i.get('Status') for i in instances]!r}"
        )
        time.sleep(5)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control",
      "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """StartDeviceAuthorization requires the clientSecret of the clientId's own registration: a
    malformed secret and another registration's valid secret are refused, while the client's own
    secret succeeds. An emulator that accepts any secret for a known clientId fails here.
    """
    oidc = ctx.client("sso-oidc")
    start_url = _start_url(ctx)

    client_a = oidc.register_client(clientName=ctx.unique_name("sim2real-behav-oidc-a-"),
                                    clientType="public")
    client_b = oidc.register_client(clientName=ctx.unique_name("sim2real-behav-oidc-b-"),
                                    clientType="public")
    assert client_a["clientSecret"] != client_b["clientSecret"], "two registrations shared a secret"

    def start(secret):
        return lambda: oidc.start_device_authorization(clientId=client_a["clientId"],
                                                       clientSecret=secret, startUrl=start_url)

    code, message = _error(start("sim2real-not-a-client-secret"))
    assert code == "InvalidClientException", (
        f"a malformed client secret got {code!r} ({message!r}), expected 'InvalidClientException'"
    )
    assert message == "Invalid client secret provided", f"malformed-secret message was {message!r}"

    code, message = _error(start(client_b["clientSecret"]))
    assert code == "InvalidClientException", (
        f"client A's id with client B's secret got {code!r} ({message!r}), "
        f"expected 'InvalidClientException'"
    )
    assert message == "Invalid client ID provided", f"cross-client secret message was {message!r}"

    auth = start(client_a["clientSecret"])()
    assert auth["deviceCode"] and auth["userCode"], (
        f"the positive control returned no device or user code: {sorted(auth)!r}"
    )
    assert int(auth["expiresIn"]) > 0, f"the positive control's expiresIn was {auth['expiresIn']!r}"
    assert auth["verificationUriComplete"].endswith(auth["userCode"]), (
        "verificationUriComplete does not carry the userCode it was issued with"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
