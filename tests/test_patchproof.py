import hashlib, json
import pytest

def addr(value): return "0x" + bytes(value).hex()
def sha(text): return hashlib.sha256(text.encode()).hexdigest()

POLICY = "A remediation must match the advisory root cause and affected range, include regression tests, document residual risk, and be independently reproduced before a receipt can be published."
COMMIT = "1" * 40
ADVISORY = "# Advisory\nParser confusion permits authorization bypass in versions <2.4.1. Reproduce using nested duplicate scope fields."
PATCH = "# Patch\nVersion 2.4.1 rejects duplicate scope fields before authorization. Added regression tests for nested, reordered, and malformed payloads. Residual risk: alternate parsers must use canonical mode."
VERIFY = "# Independent verification\nReproduced bypass on 2.4.0. The same corpus is rejected on 2.4.1. New regression tests pass; canonical parser configuration confirmed."

def setup(contract, owner, maintainer, reviewer):
    contract.register_project("parser-core", addr(maintainer), addr(reviewer), "acme/parser-core", "audit-lab/parser-verification", POLICY)

def open_and_submit(contract, vm, owner, maintainer, reviewer):
    advisory_url=f"https://raw.githubusercontent.com/acme/parser-core/{COMMIT}/ADVISORY.md"
    patch_url=f"https://raw.githubusercontent.com/acme/parser-core/{COMMIT}/PATCH.md"
    verify_url=f"https://raw.githubusercontent.com/audit-lab/parser-verification/{COMMIT}/VERIFY.md"
    with vm.prank(maintainer):
        contract.open_case(addr(owner),"parser-core","cve-2026-001",advisory_url,sha(ADVISORY),len(ADVISORY.encode()),"2.4.1","<2.4.1")
        contract.submit_patch(addr(owner),"parser-core","cve-2026-001",patch_url,sha(PATCH),len(PATCH.encode()),"patch-001")
    with vm.prank(reviewer):
        contract.submit_verification(addr(owner),"parser-core","cve-2026-001",verify_url,sha(VERIFY),len(VERIFY.encode()),"verify-001")
    return advisory_url, patch_url, verify_url

def test_deploys_and_reports_schema(direct_deploy):
    contract=direct_deploy("contracts/patchproof.py")
    assert json.loads(contract.get_contract_version()) == {"name":"PatchProof","schema":"semantic-security-remediation-v1","version":1}

def test_rejects_invalid_and_non_independent_policy(direct_deploy, direct_vm, direct_alice, direct_bob):
    contract=direct_deploy("contracts/patchproof.py")
    with direct_vm.expect_revert("INVALID_MAINTAINER_ADDRESS"):
        contract.register_project("parser-core","0x1234",addr(direct_alice),"acme/parser","audit/parser",POLICY)
    with direct_vm.expect_revert("REVIEWER_MUST_BE_INDEPENDENT"):
        contract.register_project("parser-core",addr(direct_alice),addr(direct_alice),"acme/parser","audit/parser",POLICY)
    with direct_vm.expect_revert("REVIEWER_REPOSITORY_NOT_INDEPENDENT"):
        contract.register_project("parser-core",addr(direct_alice),addr(direct_bob),"acme/parser","acme/parser",POLICY)
    with direct_vm.expect_revert("CONTROLLER_CANNOT_BE_REVIEWER"):
        contract.register_project("parser-core",addr(direct_alice),addr(direct_vm._sender),"acme/parser","audit/parser",POLICY)

def test_controller_namespace_prevents_squatting(direct_deploy, direct_vm, direct_owner, direct_alice, direct_bob):
    contract=direct_deploy("contracts/patchproof.py"); setup(contract,direct_owner,direct_alice,direct_bob)
    with direct_vm.prank(direct_bob):
        contract.register_project("parser-core",addr(direct_alice),addr(direct_owner),"other/parser","other/audit",POLICY)
    assert json.loads(contract.get_project(addr(direct_owner),"parser-core"))["repository"] == "acme/parser-core"
    assert json.loads(contract.get_project(addr(direct_bob),"parser-core"))["repository"] == "other/parser"

def test_sender_roles_and_source_scope_are_enforced(direct_deploy, direct_vm, direct_owner, direct_alice, direct_bob):
    contract=direct_deploy("contracts/patchproof.py"); setup(contract,direct_owner,direct_alice,direct_bob)
    url=f"https://raw.githubusercontent.com/acme/parser-core/{COMMIT}/ADVISORY.md"
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("MAINTAINER_ONLY"):
        contract.open_case(addr(direct_owner),"parser-core","cve-2026-001",url,sha(ADVISORY),len(ADVISORY.encode()),"2.4.1","<2.4.1")
    with direct_vm.prank(direct_alice):
        contract.open_case(addr(direct_owner),"parser-core","cve-2026-001",url,sha(ADVISORY),len(ADVISORY.encode()),"2.4.1","<2.4.1")
        with direct_vm.expect_revert("INVALID_PATCH_URL"):
            contract.submit_patch(addr(direct_owner),"parser-core","cve-2026-001",f"https://raw.githubusercontent.com/evil/repo/{COMMIT}/PATCH.md",sha(PATCH),len(PATCH.encode()),"patch-001")

def test_full_remediation_lifecycle_and_replay_guard(direct_deploy, direct_vm, direct_owner, direct_alice, direct_bob):
    contract=direct_deploy("contracts/patchproof.py"); setup(contract,direct_owner,direct_alice,direct_bob)
    urls=open_and_submit(contract,direct_vm,direct_owner,direct_alice,direct_bob)
    direct_vm.mock_web(r"ADVISORY.md",{"method":"GET","status":200,"body":ADVISORY})
    direct_vm.mock_web(r"PATCH.md",{"method":"GET","status":200,"body":PATCH})
    direct_vm.mock_web(r"VERIFY.md",{"method":"GET","status":200,"body":VERIFY})
    direct_vm.mock_llm(r"Assess security remediation evidence",'{"verdict":"REMEDIATED"}')
    assert contract.assess_case(addr(direct_owner),"parser-core","cve-2026-001") == "REMEDIATED"
    state=json.loads(contract.get_case(addr(direct_owner),"parser-core","cve-2026-001"))
    with direct_vm.prank(direct_alice):
        receipt=contract.publish_receipt(addr(direct_owner),"parser-core","cve-2026-001",state["assessment_digest"])
        with direct_vm.expect_revert("RECEIPT_ALREADY_PUBLISHED"):
            contract.publish_receipt(addr(direct_owner),"parser-core","cve-2026-001",state["assessment_digest"])
    assert json.loads(contract.get_case(addr(direct_owner),"parser-core","cve-2026-001"))["receipt"] == receipt

@pytest.mark.parametrize("rejected_verdict", ["PARTIAL", "CONFLICTED", "UNSAFE"])
def test_rejected_assessment_cannot_publish(direct_deploy, direct_vm, direct_owner, direct_alice, direct_bob, rejected_verdict):
    contract=direct_deploy("contracts/patchproof.py"); setup(contract,direct_owner,direct_alice,direct_bob)
    open_and_submit(contract,direct_vm,direct_owner,direct_alice,direct_bob)
    direct_vm.mock_web(r"ADVISORY.md",{"method":"GET","status":200,"body":ADVISORY})
    direct_vm.mock_web(r"PATCH.md",{"method":"GET","status":200,"body":PATCH})
    direct_vm.mock_web(r"VERIFY.md",{"method":"GET","status":200,"body":VERIFY})
    direct_vm.mock_llm(r"Assess security remediation evidence",json.dumps({"verdict":rejected_verdict}))
    assert contract.assess_case(addr(direct_owner),"parser-core","cve-2026-001") == rejected_verdict
    state=json.loads(contract.get_case(addr(direct_owner),"parser-core","cve-2026-001"))
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("CASE_NOT_REMEDIATED"):
        contract.publish_receipt(addr(direct_owner),"parser-core","cve-2026-001",state["assessment_digest"])

def test_unavailable_source_is_retryable(direct_deploy, direct_vm, direct_owner, direct_alice, direct_bob):
    contract=direct_deploy("contracts/patchproof.py"); setup(contract,direct_owner,direct_alice,direct_bob)
    open_and_submit(contract,direct_vm,direct_owner,direct_alice,direct_bob)
    direct_vm.mock_web(r"ADVISORY.md",{"method":"GET","status":503,"body":"down"})
    direct_vm.mock_web(r"PATCH.md",{"method":"GET","status":200,"body":PATCH})
    direct_vm.mock_web(r"VERIFY.md",{"method":"GET","status":200,"body":VERIFY})
    assert contract.assess_case(addr(direct_owner),"parser-core","cve-2026-001") == "UNAVAILABLE"
    assert json.loads(contract.get_case(addr(direct_owner),"parser-core","cve-2026-001"))["status"] == "READY_FOR_ASSESSMENT"
    assert contract.assess_case(addr(direct_owner),"parser-core","cve-2026-001") == "UNAVAILABLE"
    assert json.loads(contract.get_case(addr(direct_owner),"parser-core","cve-2026-001"))["status"] == "READY_FOR_ASSESSMENT"

def test_unauthorized_submission_and_digest_binding(direct_deploy, direct_vm, direct_owner, direct_alice, direct_bob):
    contract=direct_deploy("contracts/patchproof.py"); setup(contract,direct_owner,direct_alice,direct_bob)
    advisory_url=f"https://raw.githubusercontent.com/acme/parser-core/{COMMIT}/ADVISORY.md"
    with direct_vm.prank(direct_alice):
        contract.open_case(addr(direct_owner),"parser-core","cve-2026-001",advisory_url,sha(ADVISORY),len(ADVISORY.encode()),"2.4.1","<2.4.1")
    patch_url=f"https://raw.githubusercontent.com/acme/parser-core/{COMMIT}/PATCH.md"
    with direct_vm.prank(direct_bob), direct_vm.expect_revert("MAINTAINER_ONLY"):
        contract.submit_patch(addr(direct_owner),"parser-core","cve-2026-001",patch_url,sha(PATCH),len(PATCH.encode()),"patch-001")
    with direct_vm.prank(direct_alice):
        contract.submit_patch(addr(direct_owner),"parser-core","cve-2026-001",patch_url,sha(PATCH),len(PATCH.encode()),"patch-001")
    verify_url=f"https://raw.githubusercontent.com/audit-lab/parser-verification/{COMMIT}/VERIFY.md"
    with direct_vm.prank(direct_alice), direct_vm.expect_revert("REVIEWER_ONLY"):
        contract.submit_verification(addr(direct_owner),"parser-core","cve-2026-001",verify_url,sha(VERIFY),len(VERIFY.encode()),"verify-001")
