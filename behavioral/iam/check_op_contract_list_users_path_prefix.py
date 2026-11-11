"""op-contract-listUsers-path-prefix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listUsers-path-prefix"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PathPrefix filtering returns exactly the user we created under our unique path; a bogus
    pagination Marker is rejected by the service."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-batch09-usr")
    path = f"/{suffix}/"
    user_name = f"{suffix}-user"
    iam.create_user(UserName=user_name, Path=path, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    resp = iam.list_users(PathPrefix=path)
    users = resp["Users"]
    assert len(users) == 1, f"expected exactly 1 user under {path}, got {users}"
    assert users[0]["UserName"] == user_name
    assert users[0]["Path"] == path

    # Error boundary: a Marker IAM never issued is a service-side rejection, not something
    # botocore's client-side model validation can catch (unlike a MaxItems range violation).
    try:
        iam.list_users(Marker="not-a-real-continuation-token")
        raise AssertionError("expected a service-side error for a bogus pagination Marker")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationError", f"unexpected error code {code}: {exc}"
        message = exc.response["Error"].get("Message")
        assert message == "Invalid Marker.", f"expected message 'Invalid Marker.', got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
