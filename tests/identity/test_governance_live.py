from agent_gate.identity import connected_agents as ca
from agent_gate.identity import governance_live as gl
from agent_gate.records import chain_receipt


def _append(chain, signer, *, sid="sess-1", tool="Bash"):
    return chain_receipt.build_record(
        signer=signer, chain=chain, tool=tool, payload={}, executor_id=sid,
        executor_role="agent", dispatch_id=sid,
    )


def test_session_with_receipts_gets_boundary_and_recent_tail(chain, issuer, trust_store):
    _append(chain, issuer)

    def lane_fn(actor):
        assert actor == "sess-1"
        return {"ok": True, "capabilities": [{"verdict": "auto", "escalation": False}],
                "provenance": {"max_grade": "L2"}}

    out = gl.session_governance(chain=chain, lane_capabilities_fn=lane_fn, trust_store=trust_store)
    assert out["session_count"] == 1
    s = out["sessions"][0]
    assert s["session_id"] == "sess-1"
    assert s["verdict"] == "auto"
    assert s["grade"] == "L2"
    assert len(s["recent"]) == 1


def test_no_lane_fn_fails_closed_to_refused(chain, issuer, trust_store):
    _append(chain, issuer)
    out = gl.session_governance(chain=chain, trust_store=trust_store)
    assert out["sessions"][0]["verdict"] == "refused"


def test_broken_lane_fn_fails_closed(chain, issuer, trust_store):
    _append(chain, issuer)

    def broken(actor):
        raise RuntimeError("boom")

    out = gl.session_governance(chain=chain, lane_capabilities_fn=broken, trust_store=trust_store)
    assert out["sessions"][0]["verdict"] == "refused"


def test_receipt_without_session_of_match_is_ignored(chain, issuer, trust_store):
    _append(chain, issuer)
    out = gl.session_governance(chain=chain, trust_store=trust_store, session_of=lambda r: None)
    assert out["session_count"] == 0


def test_connected_presence_joined_by_session_id(tmp_path, chain, issuer, trust_store):
    root = str(tmp_path)
    ca.register_connection(agent="claude-code", root=root, session_id="sess-1")
    _append(chain, issuer)
    out = gl.session_governance(chain=chain, root=root, trust_store=trust_store)
    s = out["sessions"][0]
    assert s["connected"] is True
    assert s["pid"] is not None


def test_idle_connection_listed_separately(tmp_path, chain, trust_store):
    root = str(tmp_path)
    ca.register_connection(agent="claude-code", root=root, session_id="sess-idle")
    out = gl.session_governance(chain=chain, root=root, trust_store=trust_store)
    assert out["session_count"] == 0
    assert len(out["connected_only"]) == 1
    assert out["connected_only"][0]["session_id"] == "sess-idle"


def test_unsigned_receipt_never_shows_as_witnessed(chain):
    chain.append({"run_id": "sess-1", "tool": "Bash"})
    out = gl.session_governance(chain=chain)
    assert out["session_count"] == 0


def test_unsigned_receipt_never_shows_even_with_trust_store(chain, trust_store):
    chain.append({"run_id": "sess-1", "tool": "Bash"})
    out = gl.session_governance(chain=chain, trust_store=trust_store)
    assert out["session_count"] == 0


def test_tampered_receipt_never_shows_as_witnessed(chain, issuer, trust_store):
    _append(chain, issuer)
    chain.all()[-1]["receipt"]["tool"] = "Tampered"
    out = gl.session_governance(chain=chain, trust_store=trust_store)
    assert out["session_count"] == 0


def test_missing_trust_store_fails_closed_even_with_real_receipt(chain, issuer):
    _append(chain, issuer)
    out = gl.session_governance(chain=chain)
    assert out["session_count"] == 0
