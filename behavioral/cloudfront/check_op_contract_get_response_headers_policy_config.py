"""op-contract-getResponseHeadersPolicyConfig."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getResponseHeadersPolicyConfig"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResponseHeadersPolicyConfig returns exactly the config that was set; a bogus Id yields NoSuchResponseHeadersPolicy."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-rhpc-")
    config = {
        "Name": name,
        "Comment": "sim2real behavioral check config",
        "RemoveHeadersConfig": {
            "Quantity": 1,
            "Items": [{"Header": "X-Powered-By"}],
        },
    }
    created = cf.create_response_headers_policy(ResponseHeadersPolicyConfig=config)
    policy_id = created["ResponseHeadersPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_policy(cf, policy_id))

    got = cf.get_response_headers_policy_config(Id=policy_id)
    cfg = got["ResponseHeadersPolicyConfig"]
    assert cfg["Name"] == name, f"expected Name {name!r}, got {cfg['Name']!r}"
    assert cfg["Comment"] == "sim2real behavioral check config", (
        f"expected Comment 'sim2real behavioral check config', got {cfg['Comment']!r}"
    )
    assert cfg["RemoveHeadersConfig"]["Quantity"] == 1, (
        f"expected RemoveHeadersConfig.Quantity 1, got {cfg['RemoveHeadersConfig']['Quantity']!r}"
    )
    assert cfg["RemoveHeadersConfig"]["Items"][0]["Header"] == "X-Powered-By", (
        f"expected RemoveHeadersConfig.Items[0].Header 'X-Powered-By', "
        f"got {cfg['RemoveHeadersConfig']['Items'][0]['Header']!r}"
    )

    code, msg = _error(lambda: cf.get_response_headers_policy_config(Id="NOSUCHPOLICYID000001"))
    assert code == "NoSuchResponseHeadersPolicy", f"expected NoSuchResponseHeadersPolicy, got {code}"
    assert msg == "Id format is invalid", f"unexpected NoSuchResponseHeadersPolicy message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_policy(cf, policy_id):
    cur = cf.get_response_headers_policy(Id=policy_id)
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=cur["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
