"""namespace-create-rejects-combined-manage-and-explicit-admin-password."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-create-rejects-combined-manage-and-explicit-admin-password"
GROUP = "negative-classes"
SERVICES = ["redshift-serverless"]


_VALIDATION = (
    "ValidationException",
    "The AdminUserPassword parameter cannot be provided if ManagedAdminPassword is true.",
)


def _code(exc: ClientError) -> str:
    return exc.response["Error"]["Code"]


def expect_error(fn, code, message):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(
        f"expected the call to be rejected with {(code, message)!r}, but it SUCCEEDED: {result!r}"
    )


def _namespace_or_absent(rss, name: str):
    try:
        return rss.get_namespace(namespaceName=name)["namespace"]
    except ClientError as exc:
        if _code(exc) == "ResourceNotFoundException":
            return None
        raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNamespace with manageAdminPassword true and adminUserPassword set is refused, leaving
    no namespace behind; the same call without the password succeeds.

    Reference: https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_CreateNamespace.html
    """
    rss = ctx.client("redshift-serverless")

    rejected_name = ctx.unique_name("sim2real-behav-rssreject-")
    expect_error(
        lambda: rss.create_namespace(
            namespaceName=rejected_name,
            adminUsername="admin1",
            adminUserPassword="Sim2realWg7Qmx9Z",
            manageAdminPassword=True,
        ),
        *_VALIDATION,
    )

    absent = _namespace_or_absent(rss, rejected_name)
    assert absent is None, f"the refused CreateNamespace must leave no namespace, found {absent!r}"

    control_name = ctx.unique_name("sim2real-behav-rsscontrol-")
    created = rss.create_namespace(
        namespaceName=control_name, adminUsername="admin1", manageAdminPassword=True
    )["namespace"]
    ctx.on_cleanup(lambda: rss.delete_namespace(namespaceName=control_name))
    assert created["namespaceName"] == control_name, (
        f"the legal neighbor (manageAdminPassword alone, no adminUserPassword) must succeed, "
        f"got {created!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
