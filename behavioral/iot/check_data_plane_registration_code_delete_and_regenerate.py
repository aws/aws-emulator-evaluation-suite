"""data-plane-registration-code-delete-and-regenerate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-plane-registration-code-delete-and-regenerate"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-registration-code")
def run(ctx) -> None:
    """GetRegistrationCode is idempotent while the code exists, but after
    DeleteRegistrationCode the next GetRegistrationCode call mints a fresh, distinct code
    rather than replaying the deleted one."""
    iot = ctx.client("iot")

    code1 = iot.get_registration_code()["registrationCode"]
    # Calling Get again without deleting must replay the exact same code (no silent rotation).
    code1_again = iot.get_registration_code()["registrationCode"]
    assert code1_again == code1, (
        f"GetRegistrationCode is not idempotent: expected {code1!r}, got {code1_again!r}"
    )
    assert len(code1) == 64, f"expected a 64-character registration code, got {code1!r}"

    iot.delete_registration_code()
    ctx.on_cleanup(lambda: _delete_code_ignore(iot))

    code2 = iot.get_registration_code()["registrationCode"]
    assert len(code2) == 64, (
        f"expected a 64-character registration code after regeneration, got {code2!r}"
    )
    assert code2 != code1, (
        f"expected a fresh code after DeleteRegistrationCode, got the same code back: {code2!r}"
    )

    # And the newly minted code is itself stable until deleted again.
    code2_again = iot.get_registration_code()["registrationCode"]
    assert code2_again == code2, (
        f"GetRegistrationCode is not idempotent after regeneration: expected {code2!r}, got {code2_again!r}"
    )


def _delete_code_ignore(iot) -> None:
    try:
        iot.delete_registration_code()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
