"""delete-registration-code-triggers-regeneration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-registration-code-triggers-regeneration"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-registration-code")
def run(ctx) -> None:
    """GetRegistrationCode returns the same code twice, and after DeleteRegistrationCode it
    returns a different one."""
    iot = ctx.client("iot")

    first_code = iot.get_registration_code()["registrationCode"]
    first_code_again = iot.get_registration_code()["registrationCode"]
    assert first_code_again == first_code, (
        f"registration code changed with no delete in between: {first_code!r} -> {first_code_again!r}"
    )

    iot.delete_registration_code()

    second_code = iot.get_registration_code()["registrationCode"]

    assert second_code != first_code, "registration code was reused instead of regenerated"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
