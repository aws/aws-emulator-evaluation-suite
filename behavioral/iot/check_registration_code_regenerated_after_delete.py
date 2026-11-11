"""registration-code-regenerated-after-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "registration-code-regenerated-after-delete"
GROUP = "visibility-timeout-ttl"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-registration-code")
def run(ctx) -> None:
    """After DeleteRegistrationCode, the next GetRegistrationCode mints a fresh code
    rather than reviving the deleted one."""
    iot = ctx.client("iot")

    # Ensure a code exists for the account (GetRegistrationCode creates one on first call).
    first_code = iot.get_registration_code()["registrationCode"]
    # Calling it again without deleting must be stable (same code, not regenerated).
    same_code = iot.get_registration_code()["registrationCode"]
    assert same_code == first_code, (
        f"registration code changed without a delete: first={first_code!r} same={same_code!r}"
    )

    iot.delete_registration_code()

    second_code = iot.get_registration_code()["registrationCode"]
    assert second_code != first_code, (
        f"registration code was reused instead of regenerated: first={first_code!r} second={second_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
