"""op-contract-getApplication."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getApplication"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-get-application-contract"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetApplication returns the exact Name/Description written at creation; a
    nonexistent ApplicationId is rejected with ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    name = ctx.unique_name("sim2real-app-")
    created = appconfig.create_application(Name=name, Description="behavioral check app", Tags=_TAGS)
    app_id = created["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    resp = appconfig.get_application(ApplicationId=app_id)
    assert resp["Id"] == app_id, f"expected Id {app_id!r}, got {resp['Id']!r}"
    assert resp["Name"] == name, f"expected Name {name!r}, got {resp['Name']!r}"
    assert resp["Description"] == "behavioral check app", (
        f"expected Description 'behavioral check app', got {resp['Description']!r}"
    )

    # error boundary: application never existed
    bogus_id = "z9z9z9z9"
    code, code_msg = _error(lambda: appconfig.get_application(ApplicationId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert code_msg == (
        f"Application with Id {bogus_id} could not be found for account {account}."
    ), f"unexpected message: {code_msg!r}"


def _error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
