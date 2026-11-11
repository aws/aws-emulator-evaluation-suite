"""policy-put-get-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "policy-put-get-delete-lifecycle"
GROUP = "state"
SERVICES = ["mediaconvert"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPolicy creates/overwrites the account-level input policy, GetPolicy reflects it
    exactly, and DeletePolicy reverts the account to having no policy (GetPolicy keeps
    returning 200 with no Policy field, not NotFoundException)."""
    mc = ctx.client("mediaconvert")

    original = None
    try:
        resp = mc.get_policy()
        original = resp.get("Policy")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise

    def _restore():
        if original is None:
            try:
                mc.delete_policy()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise
        else:
            mc.put_policy(Policy=original)

    ctx.on_cleanup(_restore)

    new_policy = {"HttpInputs": "DISALLOWED", "HttpsInputs": "ALLOWED", "S3Inputs": "ALLOWED"}
    put_resp = mc.put_policy(Policy=new_policy)["Policy"]
    assert put_resp["HttpInputs"] == "DISALLOWED", f"PutPolicy HttpInputs: {put_resp!r}"
    assert put_resp["HttpsInputs"] == "ALLOWED", f"PutPolicy HttpsInputs: {put_resp!r}"
    assert put_resp["S3Inputs"] == "ALLOWED", f"PutPolicy S3Inputs: {put_resp!r}"

    got = mc.get_policy()["Policy"]
    assert got["HttpInputs"] == "DISALLOWED", f"GetPolicy HttpInputs: {got!r}"
    assert got["HttpsInputs"] == "ALLOWED", f"GetPolicy HttpsInputs: {got!r}"
    assert got["S3Inputs"] == "ALLOWED", f"GetPolicy S3Inputs: {got!r}"

    mc.delete_policy()
    after_delete = mc.get_policy()
    assert after_delete.get("Policy") is None, f"expected no policy after delete, got {after_delete!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
