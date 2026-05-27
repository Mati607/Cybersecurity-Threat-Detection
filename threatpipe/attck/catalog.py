"""Bundled subset of the MITRE ATT&CK enterprise catalog.

Carrying a tiny, curated technique catalog inline lets the API and
dashboard answer "do we have a rule for T1059?" without forcing every
deployment to fetch the full taxonomy. Operators can swap in the
upstream STIX bundle via :meth:`AttckCatalog.load_stix` for the full
~600-technique tree.

The data here covers the techniques referenced by the bundled rule
catalog plus the most common ones SOC analysts care about, with their
canonical tactic mapping.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


class Tactic(str, enum.Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


TACTICS: List[Tactic] = list(Tactic)


@dataclass
class Technique:
    technique_id: str
    name: str
    tactics: List[Tactic]
    description: str = ""
    is_subtechnique: bool = False
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)

    @property
    def parent_id(self) -> Optional[str]:
        if "." in self.technique_id:
            return self.technique_id.split(".", 1)[0]
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactics": [t.value for t in self.tactics],
            "description": self.description,
            "is_subtechnique": self.is_subtechnique,
            "platforms": list(self.platforms),
            "data_sources": list(self.data_sources),
            "parent_id": self.parent_id,
        }


DEFAULT_TECHNIQUES: List[Technique] = [
    Technique("T1003", "OS Credential Dumping", [Tactic.CREDENTIAL_ACCESS],
              "Adversaries may attempt to dump credentials to obtain account login material.",
              platforms=["Windows", "Linux", "macOS"]),
    Technique("T1003.001", "LSASS Memory", [Tactic.CREDENTIAL_ACCESS],
              "Access LSASS process memory to extract credentials.",
              is_subtechnique=True, platforms=["Windows"]),
    Technique("T1003.007", "Proc Filesystem", [Tactic.CREDENTIAL_ACCESS],
              "Read /proc/<pid>/maps to extract credentials.",
              is_subtechnique=True, platforms=["Linux"]),
    Technique("T1027", "Obfuscated Files or Information", [Tactic.DEFENSE_EVASION],
              "Adversaries encode or encrypt artifacts to bypass static analysis.",
              platforms=["Windows", "Linux", "macOS"]),
    Technique("T1055", "Process Injection", [Tactic.DEFENSE_EVASION, Tactic.PRIVILEGE_ESCALATION],
              "Inject code into another process to evade defenses or elevate privileges.",
              platforms=["Windows", "Linux", "macOS"]),
    Technique("T1059", "Command and Scripting Interpreter", [Tactic.EXECUTION],
              "Abuse command interpreters (PowerShell, bash, cmd, Python) for execution.",
              platforms=["Windows", "Linux", "macOS"]),
    Technique("T1059.001", "PowerShell", [Tactic.EXECUTION], "Use PowerShell to execute commands.",
              is_subtechnique=True, platforms=["Windows"]),
    Technique("T1059.003", "Windows Command Shell", [Tactic.EXECUTION], "Use cmd.exe to execute commands.",
              is_subtechnique=True, platforms=["Windows"]),
    Technique("T1059.004", "Unix Shell", [Tactic.EXECUTION], "Use sh/bash to execute commands.",
              is_subtechnique=True, platforms=["Linux", "macOS"]),
    Technique("T1071", "Application Layer Protocol", [Tactic.COMMAND_AND_CONTROL],
              "Use application-layer protocols for command and control.",
              platforms=["Windows", "Linux", "macOS"]),
    Technique("T1071.001", "Web Protocols", [Tactic.COMMAND_AND_CONTROL],
              "HTTPS/HTTP used as a C2 channel.", is_subtechnique=True),
    Technique("T1078", "Valid Accounts", [Tactic.DEFENSE_EVASION, Tactic.PERSISTENCE,
                                            Tactic.PRIVILEGE_ESCALATION, Tactic.INITIAL_ACCESS],
              "Adversaries use stolen credentials for access."),
    Technique("T1082", "System Information Discovery", [Tactic.DISCOVERY],
              "Gather host information."),
    Technique("T1083", "File and Directory Discovery", [Tactic.DISCOVERY],
              "Enumerate files and directories."),
    Technique("T1110", "Brute Force", [Tactic.CREDENTIAL_ACCESS],
              "Repeatedly attempt to authenticate."),
    Technique("T1190", "Exploit Public-Facing Application", [Tactic.INITIAL_ACCESS],
              "Exploit an internet-exposed service."),
    Technique("T1486", "Data Encrypted for Impact", [Tactic.IMPACT],
              "Ransomware-style encryption of files."),
    Technique("T1490", "Inhibit System Recovery", [Tactic.IMPACT],
              "Delete shadow copies / backups to prevent recovery."),
    Technique("T1547", "Boot or Logon Autostart Execution", [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION],
              "Establish persistence via autostart locations."),
    Technique("T1547.001", "Registry Run Keys / Startup Folder", [Tactic.PERSISTENCE],
              "Persistence via HKLM/HKCU Run keys or Startup folder.", is_subtechnique=True),
    Technique("T1548", "Abuse Elevation Control Mechanism", [Tactic.PRIVILEGE_ESCALATION,
                                                              Tactic.DEFENSE_EVASION],
              "Abuse sudo/UAC/SUID to elevate privileges."),
    Technique("T1567", "Exfiltration Over Web Service", [Tactic.EXFILTRATION],
              "Push data to a legitimate web service."),
    Technique("T1571", "Non-Standard Port", [Tactic.COMMAND_AND_CONTROL],
              "C2 over an uncommon port."),
    Technique("T1595", "Active Scanning", [Tactic.RECONNAISSANCE], "Network scanning."),
    Technique("T1620", "Reflective Code Loading", [Tactic.DEFENSE_EVASION],
              "Load code into memory without writing to disk."),
    Technique("T1219", "Remote Access Software", [Tactic.COMMAND_AND_CONTROL],
              "Install remote-access tools (TeamViewer, AnyDesk, ...)."),
    Technique("T1037", "Boot or Logon Initialization Scripts", [Tactic.PERSISTENCE,
                                                                  Tactic.PRIVILEGE_ESCALATION],
              "Persistence via init / login / RC scripts."),
    Technique("T1574", "Hijack Execution Flow", [Tactic.PERSISTENCE, Tactic.PRIVILEGE_ESCALATION,
                                                   Tactic.DEFENSE_EVASION],
              "DLL search-order hijack, LD_PRELOAD, etc."),
    Technique("T1018", "Remote System Discovery", [Tactic.DISCOVERY], "Enumerate remote hosts."),
    Technique("T1021", "Remote Services", [Tactic.LATERAL_MOVEMENT],
              "Move laterally via SSH, RDP, SMB, WinRM, etc."),
    Technique("T1021.001", "Remote Desktop Protocol", [Tactic.LATERAL_MOVEMENT],
              "Move laterally via RDP.", is_subtechnique=True),
    Technique("T1021.004", "SSH", [Tactic.LATERAL_MOVEMENT],
              "Move laterally via SSH.", is_subtechnique=True),
    Technique("T1496", "Resource Hijacking", [Tactic.IMPACT],
              "Hijack compute resources for crypto mining."),
    Technique("T1499", "Endpoint Denial of Service", [Tactic.IMPACT],
              "Exhaust endpoint resources."),
    Technique("T1041", "Exfiltration Over C2 Channel", [Tactic.EXFILTRATION],
              "Exfil data back over the existing C2 channel."),
    Technique("T1560", "Archive Collected Data", [Tactic.COLLECTION], "Compress / encrypt loot prior to exfil."),
    Technique("T1098", "Account Manipulation", [Tactic.PERSISTENCE],
              "Modify account attributes to preserve access."),
    Technique("T1485", "Data Destruction", [Tactic.IMPACT], "Destroy data on target systems."),
    Technique("T1505", "Server Software Component", [Tactic.PERSISTENCE],
              "Web shells, malicious modules, IIS components."),
    Technique("T1505.003", "Web Shell", [Tactic.PERSISTENCE],
              "Drop a web shell on a public-facing service.", is_subtechnique=True),
    Technique("T1583", "Acquire Infrastructure", [Tactic.RESOURCE_DEVELOPMENT],
              "Stand up C2 / phishing infrastructure."),
    Technique("T1566", "Phishing", [Tactic.INITIAL_ACCESS], "Email-borne malware or credential lures."),
    Technique("T1566.001", "Spearphishing Attachment", [Tactic.INITIAL_ACCESS],
              "Targeted attachment-based phishing.", is_subtechnique=True),
    Technique("T1078.004", "Cloud Accounts", [Tactic.INITIAL_ACCESS, Tactic.PERSISTENCE,
                                                Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION],
              "Reuse cloud accounts.", is_subtechnique=True),
]


class AttckCatalog:
    def __init__(self, techniques: Optional[Iterable[Technique]] = None) -> None:
        self._by_id: Dict[str, Technique] = {}
        for tech in techniques or DEFAULT_TECHNIQUES:
            self._by_id[tech.technique_id] = tech

    # --- accessors -----------------------------------------------

    def get(self, technique_id: str) -> Optional[Technique]:
        if not technique_id:
            return None
        tech = self._by_id.get(technique_id)
        if tech is not None:
            return tech
        if "." in technique_id:
            return self._by_id.get(technique_id.split(".", 1)[0])
        return None

    def all(self) -> List[Technique]:
        return sorted(self._by_id.values(), key=lambda t: t.technique_id)

    def by_tactic(self, tactic: Tactic) -> List[Technique]:
        return [t for t in self.all() if tactic in t.tactics]

    def tactics(self) -> List[Tactic]:
        return TACTICS

    def search(self, query: str) -> List[Technique]:
        q = query.lower()
        return [
            t for t in self.all()
            if q in t.technique_id.lower() or q in t.name.lower() or q in t.description.lower()
        ]

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self):
        return iter(self.all())

    # --- IO ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {"techniques": [t.to_dict() for t in self.all()]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttckCatalog":
        techs: List[Technique] = []
        for raw in data.get("techniques", []):
            try:
                techs.append(Technique(
                    technique_id=str(raw["technique_id"]),
                    name=str(raw.get("name", raw["technique_id"])),
                    tactics=[Tactic(t) for t in raw.get("tactics", []) if t in {x.value for x in TACTICS}],
                    description=str(raw.get("description", "")),
                    is_subtechnique=bool(raw.get("is_subtechnique", False)),
                    platforms=list(raw.get("platforms", [])),
                    data_sources=list(raw.get("data_sources", [])),
                ))
            except (KeyError, ValueError):
                continue
        return cls(techs)

    @classmethod
    def load_stix(cls, path: str | Path) -> "AttckCatalog":
        """Load the upstream MITRE ATT&CK STIX 2.x JSON bundle.

        We only consume ``attack-pattern`` objects; everything else
        (mitigations, groups, software, ...) is ignored.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        techs: List[Technique] = []
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext_refs = obj.get("external_references", []) or []
            mitre_id = next((r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"), None)
            if not mitre_id:
                continue
            kill_chain = obj.get("kill_chain_phases", []) or []
            tactics: List[Tactic] = []
            for phase in kill_chain:
                if phase.get("kill_chain_name") != "mitre-attack":
                    continue
                try:
                    tactics.append(Tactic(phase["phase_name"]))
                except (KeyError, ValueError):
                    continue
            techs.append(Technique(
                technique_id=mitre_id,
                name=obj.get("name", mitre_id),
                tactics=tactics,
                description=obj.get("description", ""),
                is_subtechnique="." in mitre_id,
                platforms=list(obj.get("x_mitre_platforms", []) or []),
                data_sources=list(obj.get("x_mitre_data_sources", []) or []),
            ))
        return cls(techs)
