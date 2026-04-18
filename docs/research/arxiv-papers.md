# Academic papers — arxiv / peer-reviewed

Capture: 2026-04-18. Pass intended to complement [prior-art.md](prior-art.md)'s "Academic landscape" note (which called the landscape "thin" and pointed only to confidential-compute attestation work). This file lists the handful of directly-relevant papers that a reviewer should actually be able to verify.

Bar for inclusion: real arxiv ID or DOI, and a concrete tie-in to aegis-hwsim's scope (persona matrix, signed-chain rescue, attestation roundtrip, or the QEMU+OVMF+swtpm stack itself). Adjacent-but-not-useful papers excluded.

## Papers

1. **SoK: Security Below the OS — A Security Analysis of UEFI** — Surve, Brodt, Yampolskiy, Elovici, Shabtai (2023). arXiv:[2311.03809](https://arxiv.org/abs/2311.03809). Threat model + MITRE-ATT&CK-style taxonomy for UEFI attacks. Useful framing for *why* the persona matrix needs to cover SB-state and firmware-version variance — and as the canonical SoK citation in README `## Motivation`.

2. **The State of Boot Integrity on Linux — a Brief Review** — ARES 2024, [doi:10.1145/3664476.3670910](https://doi.org/10.1145/3664476.3670910). Survey of shim/grub/systemd-boot/IMA/TPM ecosystem on Linux. Directly maps to the scope we test (Linux-visible signed-chain surface) and names the exact tooling gaps aegis-hwsim fills for test coverage.

3. **Remote attestation of SEV-SNP confidential VMs using e-vTPMs** — Narayanan et al. (2023). arXiv:[2303.16463](https://arxiv.org/abs/2303.16463). PCR extend + TPM2_Quote benchmarks under vTPM. Relevant to the attestation-roundtrip scenario: establishes the reference shape of a correct measurement chain and the 5x vTPM latency gap — useful when sizing scenario timeouts.

4. **UEFI Memory Forensics: A Framework for UEFI Threat Analysis** — Ben-Gurion University (2025). arXiv:[2501.16962](https://arxiv.org/abs/2501.16962). UefiMemDump / UEFIDumpAnalysis for detecting bootkits in pre-OS memory. Complementary — aegis-hwsim validates chain *integrity*; this validates chain *absence of hooks*. Potential future scenario if a persona needs to assert "no malicious image loaded".

5. **FUZZUER: Enabling Fuzzing of UEFI Interfaces on EDK-2** — NDSS 2025, [paper PDF](https://www.ndss-symposium.org/wp-content/uploads/2025-400-paper.pdf). Static-analysis-driven harness generation for EDK-2 interfaces; found 20 vulns. Not overlap — they fuzz firmware-internal interfaces; we test OS-visible signed-chain flow. Referenceable as adjacent "harness design" prior art for our `qemu::Invocation` builder docs.

## Explicit non-findings

No paper found on **persona-matrix emulation testing** or **per-laptop-vendor SB conformance**. The academic literature continues to be dominated by fuzzing and vulnerability-discovery work, not functional conformance matrices — confirming prior-art.md's original "greenfield" characterization.
