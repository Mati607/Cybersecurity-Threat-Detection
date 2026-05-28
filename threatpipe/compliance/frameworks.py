"""Bundled compliance-framework control catalogs.

Each :class:`Framework` is a set of :class:`Control`s, where a control
carries the ATT&CK techniques it is meant to detect/mitigate. That
mapping is what lets us answer "which NIST 800-53 controls do our
detection rules actually exercise?" - the bridge between the detection
engineering view (ATT&CK) and the auditor view (control families).

The catalogs here are curated subsets focused on the
detection-relevant controls; they are not a complete reproduction of
each standard. Operators can extend them via :meth:`Framework.from_dict`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class Control:
    control_id: str
    title: str
    family: str
    techniques: List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "family": self.family,
            "techniques": list(self.techniques),
            "description": self.description,
        }


@dataclass
class Framework:
    framework_id: str
    name: str
    version: str
    controls: List[Control]

    def control(self, control_id: str) -> Optional[Control]:
        for c in self.controls:
            if c.control_id == control_id:
                return c
        return None

    def families(self) -> List[str]:
        seen: List[str] = []
        for c in self.controls:
            if c.family not in seen:
                seen.append(c.family)
        return seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework_id": self.framework_id,
            "name": self.name,
            "version": self.version,
            "control_count": len(self.controls),
            "families": self.families(),
            "controls": [c.to_dict() for c in self.controls],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Framework":
        controls = [
            Control(
                control_id=str(c["control_id"]),
                title=str(c.get("title", c["control_id"])),
                family=str(c.get("family", "")),
                techniques=list(c.get("techniques", [])),
                description=str(c.get("description", "")),
            )
            for c in data.get("controls", [])
        ]
        return cls(
            framework_id=str(data["framework_id"]),
            name=str(data.get("name", data["framework_id"])),
            version=str(data.get("version", "")),
            controls=controls,
        )


# --- NIST SP 800-53 (subset) -------------------------------------

_NIST = Framework(
    framework_id="nist-800-53",
    name="NIST SP 800-53",
    version="Rev. 5",
    controls=[
        Control("AC-2", "Account Management", "Access Control",
                ["T1078", "T1098", "T1136"],
                "Manage system accounts incl. disabling on compromise."),
        Control("AC-6", "Least Privilege", "Access Control",
                ["T1548", "T1055"],
                "Enforce least privilege; detect elevation abuse."),
        Control("AU-6", "Audit Record Review & Analysis", "Audit and Accountability",
                ["T1059", "T1003", "T1486"],
                "Review and correlate audit records for indicators."),
        Control("CA-7", "Continuous Monitoring", "Assessment & Authorization",
                ["T1071", "T1571", "T1041"],
                "Ongoing monitoring of security state."),
        Control("IR-4", "Incident Handling", "Incident Response",
                ["T1486", "T1490", "T1078"],
                "Detect, analyze, contain, and recover from incidents."),
        Control("SI-3", "Malicious Code Protection", "System & Information Integrity",
                ["T1059", "T1027", "T1486", "T1620"],
                "Detect and eradicate malicious code."),
        Control("SI-4", "System Monitoring", "System & Information Integrity",
                ["T1071", "T1571", "T1003", "T1110", "T1021"],
                "Monitor for attacks and indicators of compromise."),
        Control("SC-7", "Boundary Protection", "System & Communications Protection",
                ["T1071", "T1567", "T1041"],
                "Monitor and control communications at boundaries."),
    ],
)

# --- CIS Controls v8 (subset) ------------------------------------

_CIS = Framework(
    framework_id="cis-v8",
    name="CIS Critical Security Controls",
    version="v8",
    controls=[
        Control("CIS-4", "Secure Configuration", "Foundational",
                ["T1547", "T1037", "T1574"],
                "Detect changes to autostart/boot configuration."),
        Control("CIS-5", "Account Management", "Foundational",
                ["T1078", "T1098"],
                "Manage account lifecycle and detect misuse."),
        Control("CIS-6", "Access Control Management", "Foundational",
                ["T1078", "T1548"],
                "Detect privilege escalation and access abuse."),
        Control("CIS-8", "Audit Log Management", "Foundational",
                ["T1059", "T1003", "T1110"],
                "Collect, alert on, and review audit logs."),
        Control("CIS-10", "Malware Defenses", "Foundational",
                ["T1059", "T1027", "T1486", "T1620"],
                "Detect and block malicious software."),
        Control("CIS-13", "Network Monitoring & Defense", "Organizational",
                ["T1071", "T1571", "T1041", "T1021"],
                "Detect anomalous network activity and C2."),
    ],
)

# --- PCI DSS v4 (subset) -----------------------------------------

_PCI = Framework(
    framework_id="pci-dss-v4",
    name="PCI DSS",
    version="v4.0",
    controls=[
        Control("PCI-5", "Protect Against Malicious Software", "Maintain a Vulnerability Mgmt Program",
                ["T1059", "T1027", "T1486"],
                "Anti-malware detection on cardholder systems."),
        Control("PCI-8", "Identify Users & Authenticate Access", "Strong Access Control",
                ["T1078", "T1110"],
                "Detect credential misuse and brute force."),
        Control("PCI-10", "Log & Monitor All Access", "Regularly Monitor & Test",
                ["T1059", "T1003", "T1071", "T1041"],
                "Track and monitor access to network and data."),
        Control("PCI-11", "Test Security Regularly", "Regularly Monitor & Test",
                ["T1595", "T1190"],
                "Detect scanning and exploitation attempts."),
    ],
)

# --- ISO/IEC 27001 Annex A (subset) ------------------------------

_ISO = Framework(
    framework_id="iso-27001",
    name="ISO/IEC 27001 Annex A",
    version="2022",
    controls=[
        Control("A.8.7", "Protection Against Malware", "Technological",
                ["T1059", "T1027", "T1486"],
                "Detection and prevention of malware."),
        Control("A.8.15", "Logging", "Technological",
                ["T1059", "T1003", "T1078"],
                "Produce and review event logs."),
        Control("A.8.16", "Monitoring Activities", "Technological",
                ["T1071", "T1571", "T1041", "T1021"],
                "Monitor networks/systems for anomalous behavior."),
        Control("A.5.7", "Threat Intelligence", "Organizational",
                ["T1071", "T1567", "T1041"],
                "Collect and analyze threat intelligence."),
    ],
)


FRAMEWORKS: Dict[str, Framework] = {
    f.framework_id: f for f in (_NIST, _CIS, _PCI, _ISO)
}


def get_framework(framework_id: str) -> Framework:
    fw = FRAMEWORKS.get(framework_id)
    if fw is None:
        raise KeyError(f"unknown framework: {framework_id}")
    return fw


def list_frameworks() -> List[Framework]:
    return list(FRAMEWORKS.values())
