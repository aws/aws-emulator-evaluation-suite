"""disabled-operation-feature-off-unreachable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disabled-operation-feature-off-unreachable"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListMigrations, DetachDataSource, AssociatePackages and UpdateVpcEndpoint agree on gating:
    all return DisabledOperationException, or each returns its own specific not-found/validation
    error for bogus input; a generic InternalException/BaseException fails."""
    aos = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    app_id = _create_application(ctx, aos)

    bogus_app_id = "sim2realdisop" + ctx.unique_name("x")
    bogus_app_id = "".join(c for c in bogus_app_id.lower() if c.isalnum())[:30]
    bogus_domain = _compliant_domain_name(ctx, "sim2real-disop")
    bogus_ds_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{bogus_domain}"

    # The disabled state is an account/region entitlement with no API toggle, so ListMigrations
    # serves as a canary to discover it.
    canary_code, canary_message = _error(lambda: aos.list_migrations(applicationId=bogus_app_id))
    assert canary_code not in ("InternalException", "BaseException"), (
        f"ListMigrations against a nonexistent application returned a generic failure "
        f"({canary_code}); expected a specific documented code"
    )

    probes = {
        "DetachDataSource": lambda: aos.detach_data_source(id=app_id, dataSourceArn=bogus_ds_arn),
        "AssociatePackages": lambda: aos.associate_packages(
            PackageList=[{"PackageID": "pkg-0000000000000000000000000000000000000000"}],
            DomainName=bogus_domain,
        ),
        "UpdateVpcEndpoint": lambda: aos.update_vpc_endpoint(
            VpcEndpointId="aos-000000000000000",
            VpcOptions={"SubnetIds": ["subnet-00000000000000000"], "SecurityGroupIds": ["sg-00000000000000000"]},
        ),
    }
    errors = {name: _error(fn) for name, fn in probes.items()}

    if canary_code == "DisabledOperationException":
        # Feature disabled for this account/region: every sibling op must agree.
        for name, (code, _message) in errors.items():
            assert code == "DisabledOperationException", (
                f"ListMigrations reports the feature disabled, but {name} returned "
                f"{code} instead of DisabledOperationException"
            )
    else:
        # Feature enabled: the canary itself must be a specific not-found error, and each
        # sibling answers its bogus input with its own specific not-found/validation error.
        assert canary_code == "ResourceNotFoundException", (
            f"unexpected ListMigrations error when the feature is enabled: {canary_code}"
        )
        expected_canary = f"Application {bogus_app_id} not found"
        assert canary_message == expected_canary, (
            f"ListMigrations: expected message {expected_canary!r}, got {canary_message!r}"
        )
        expected = {
            "DetachDataSource": (
                "ResourceNotFoundException",
                f"Data source {bogus_ds_arn} is not attached to application {app_id}.",
            ),
            "AssociatePackages": (
                "ValidationException",
                f"The domain {bogus_domain} does not exist.",
            ),
            "UpdateVpcEndpoint": (
                "ResourceNotFoundException",
                "The VPC endpoint doesn't exist, or you don't have access to it.",
            ),
        }
        for name, got in errors.items():
            assert got == expected[name], (
                f"{name} against bogus input: expected (code, message) {expected[name]!r}, "
                f"got {got!r}"
            )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_application(ctx, aos) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = aos.create_application(name=name[:30], tagList=[{"Key": "sim2real", "Value": "true"}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _delete_application(aos, app_id))
    _wait_application_active(aos, app_id)
    return app_id


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


def _wait_application_active(client, app_id, timeout_s=300.0, interval_s=3.0):
    """Bounded poll until the application leaves CREATING; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.get_application(id=app_id).get("status")
        if last != "CREATING":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never left CREATING within {timeout_s}s (last: {last})")


def _delete_application(client, app_id, timeout_s=600.0, interval_s=10.0):
    """Teardown: retry while an operation on the application is still in progress; an
    application that is already gone counts as deleted."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            client.delete_application(id=app_id)
            return
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
