"""service-specific-credential-quota-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-specific-credential-quota-race"
GROUP = "state-machine"
SERVICES = ["iam"]

_SERVICE_NAME = "codecommit.amazonaws.com"
_RACERS = 5


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateServiceSpecificCredential calls for one user and service yield exactly 2
    credentials with distinct ids and LimitExceeded with the exact quota message for the
    rest, and 2 are listed."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-ssc-race-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user(UserName=user_name)))

    created_ids: list[str] = []
    errors: list[str] = []
    messages: list[str] = []

    def _create() -> None:
        try:
            cred = iam.create_service_specific_credential(
                UserName=user_name, ServiceName=_SERVICE_NAME
            )["ServiceSpecificCredential"]
            created_ids.append(cred["ServiceSpecificCredentialId"])
        except Exception as exc:  # noqa: BLE001 - collecting for assertion below
            errors.append(_code_of(exc))
            messages.append(_message_of(exc))

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        futures = [pool.submit(_create) for _ in range(_RACERS)]
        for f in as_completed(futures):
            f.result()

    for cred_id in created_ids:
        ctx.on_cleanup(
            lambda cid=cred_id: _safe(
                lambda: iam.delete_service_specific_credential(
                    UserName=user_name, ServiceSpecificCredentialId=cid
                )
            )
        )

    assert len(created_ids) == 2, f"expected exactly 2 winners, got {len(created_ids)}"
    assert len(created_ids) == len(set(created_ids)), "winners must have distinct credential ids"
    assert len(errors) == _RACERS - 2, (
        f"expected {_RACERS - 2} losers rejected, got {len(errors)} ({errors})"
    )
    assert all(e == "LimitExceeded" for e in errors), (
        f"expected every loser rejected with LimitExceeded, got {errors}"
    )
    expected = "Cannot exceed quota for ContextSpecificCredentialsPerUserPerContext: 2"
    assert all(message == expected for message in messages), (
        f"expected every loser's message {expected!r}, got {messages}"
    )

    listed = iam.list_service_specific_credentials(UserName=user_name)[
        "ServiceSpecificCredentials"
    ]
    assert len(listed) == 2, (
        f"expected exactly 2 credentials to survive at the independent list read, got {len(listed)}"
    )


def _code_of(exc: Exception) -> str:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"unexpected:{type(exc).__name__}"


def _message_of(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message")
    return f"unexpected:{exc!r}"


def _safe(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
