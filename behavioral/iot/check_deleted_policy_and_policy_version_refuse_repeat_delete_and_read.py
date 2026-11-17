"""deleted-policy-and-policy-version-refuse-repeat-delete-and-read."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-policy-and-policy-version-refuse-repeat-delete-and-read"
GROUP = "policy-lifecycle"
SERVICES = ["iot"]


def _connect_doc() -> str:
    return json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"}]}
    )


def _publish_doc() -> str:
    return json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iot:Publish", "Resource": "*"}]}
    )


def _error(fn):
    """(Error.Code, Error.Message) raised by fn(); an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def expect_error(fn, code, message) -> None:
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deleted policy version and a deleted policy each refuse a repeat delete and a read with
    their own exact not-found message, and a live neighbor policy is unaffected throughout.
    """
    iot = ctx.client("iot")
    name = ctx.unique_name("sim2real-behav-iot-policy-")
    neighbor = ctx.unique_name("sim2real-behav-iot-policy-neighbor-")

    iot.create_policy(policyName=name, policyDocument=_connect_doc(), tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: iot.delete_policy(policyName=name), "ResourceNotFoundException"))

    version_id = iot.create_policy_version(
        policyName=name, policyDocument=_publish_doc(), setAsDefault=False
    )["policyVersionId"]
    ctx.on_cleanup(
        _teardown(
            lambda: iot.delete_policy_version(policyName=name, policyVersionId=version_id),
            "ResourceNotFoundException",
        )
    )

    iot.create_policy(
        policyName=neighbor, policyDocument=_connect_doc(), tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(_teardown(lambda: iot.delete_policy(policyName=neighbor), "ResourceNotFoundException"))

    got_version = iot.get_policy_version(policyName=name, policyVersionId=version_id)
    assert json.loads(got_version["policyDocument"]) == json.loads(_publish_doc()), (
        f"expected the publish document, got {got_version['policyDocument']!r}"
    )
    assert got_version["isDefaultVersion"] is False, (
        f"expected isDefaultVersion False, got {got_version['isDefaultVersion']!r}"
    )

    # The non-default version is deletable on its own, ahead of the policy itself.
    iot.delete_policy_version(policyName=name, policyVersionId=version_id)

    _version_gone = (
        "ResourceNotFoundException",
        f"Policy version does not exist (name={name}, versionId={version_id})",
    )
    expect_error(lambda: iot.get_policy_version(policyName=name, policyVersionId=version_id), *_version_gone)
    expect_error(
        lambda: iot.delete_policy_version(policyName=name, policyVersionId=version_id), *_version_gone
    )

    remaining = iot.list_policy_versions(policyName=name)["policyVersions"]
    assert [v["versionId"] for v in remaining] == ["1"], (
        f"expected only the default version 1 left, got {remaining!r}"
    )

    # The policy itself, once its only remaining version is the default one, can be deleted.
    iot.delete_policy(policyName=name)

    _policy_read_gone = ("ResourceNotFoundException", "Policy default version not found")
    _policy_delete_gone = ("ResourceNotFoundException", "Policy not found")
    expect_error(lambda: iot.get_policy(policyName=name), *_policy_read_gone)
    expect_error(lambda: iot.delete_policy(policyName=name), *_policy_delete_gone)

    all_names = set()
    marker = None
    while True:
        kwargs = {"marker": marker} if marker else {}
        page = iot.list_policies(**kwargs)
        all_names.update(p["policyName"] for p in page["policies"])
        marker = page.get("nextMarker")
        if not marker:
            break
    assert name not in all_names, f"deleted policy {name!r} still listed among {len(all_names)} policies"
    assert neighbor in all_names, f"live neighbor {neighbor!r} missing from the listing"

    # The neighbor policy, created alongside the deleted one, was never touched.
    got_neighbor = iot.get_policy(policyName=neighbor)
    assert got_neighbor["policyName"] == neighbor, (
        f"expected neighbor policyName={neighbor!r}, got {got_neighbor.get('policyName')!r}"
    )
    assert json.loads(got_neighbor["policyDocument"]) == json.loads(_connect_doc()), (
        f"neighbor document changed: {got_neighbor['policyDocument']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
