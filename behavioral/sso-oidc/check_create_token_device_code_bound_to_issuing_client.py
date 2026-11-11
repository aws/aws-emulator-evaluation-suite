"""create-token-device-code-bound-to-issuing-client."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-token-device-code-bound-to-issuing-client"
GROUP = "authorization"
SERVICES = ["sso-oidc"]

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


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
    """A device code redeems only for the client it was issued to: the same live code is refused for
    client B while it is still pending for client A, and stays pending for A afterwards. An emulator
    that looks the code up without comparing the presenting client hands B a grant.
    """
    oidc = ctx.client("sso-oidc")
    start_url = _start_url(ctx)

    client_a = oidc.register_client(clientName=ctx.unique_name("sim2real-behav-oidc-a-"),
                                    clientType="public")
    client_b = oidc.register_client(clientName=ctx.unique_name("sim2real-behav-oidc-b-"),
                                    clientType="public")
    assert client_a["clientId"] != client_b["clientId"], "two registrations returned one clientId"

    auth = oidc.start_device_authorization(clientId=client_a["clientId"],
                                           clientSecret=client_a["clientSecret"],
                                           startUrl=start_url)
    device_code = auth["deviceCode"]
    pause = max(int(auth.get("interval", 1)), 1) + 1

    def token(client):
        return lambda: oidc.create_token(clientId=client["clientId"],
                                         clientSecret=client["clientSecret"],
                                         grantType=DEVICE_GRANT, deviceCode=device_code)

    # The issuing client is told to keep waiting: the code is live and not yet approved.
    time.sleep(pause)
    code, message = _error(token(client_a))
    assert (code, message) == ("AuthorizationPendingException", "Authorization is still pending"), (
        f"client A polling its own pending device code got {code!r} {message!r}"
    )

    # Another registered client presenting the same live code is refused as an invalid grant.
    time.sleep(pause)
    code, message = _error(token(client_b))
    assert code == "InvalidGrantException", (
        f"client B presenting client A's live device code got {code!r} ({message!r}), "
        f"expected 'InvalidGrantException'"
    )
    assert message == "Invalid device code provided", (
        f"client B's refusal message was {message!r}"
    )

    # B's refused attempt neither consumed nor invalidated the code for A.
    time.sleep(pause)
    code, message = _error(token(client_a))
    assert (code, message) == ("AuthorizationPendingException", "Authorization is still pending"), (
        f"after client B's refused attempt, client A's device code answered {code!r} {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
