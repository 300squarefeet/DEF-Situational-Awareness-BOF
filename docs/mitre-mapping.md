# MITRE ATT&CK Mapping

Every BOF prints its techniques at runtime via `common::mitre::print_banner`.
This is the master index — keep in sync with each BOF's `TECHNIQUES` constant.

## Phase 1 — Canary (3 BOFs)
| BOF | Techniques | Tactic |
|---|---|---|
| uptime   | T1082 | Discovery |
| hostname | T1082 | Discovery |
| whoami   | T1033, T1134 | Discovery / Privilege Escalation |

## Phase 2 — Situational Awareness (25 BOFs)
| BOF | Techniques | Tactic |
|---|---|---|
| arp | T1018 | Discovery |
| env | T1082 | Discovery |
| ipconfig | T1016 | Discovery |
| netstat | T1049 | Discovery |
| netuser | T1087.001, T1087.002 | Discovery |
| netshare | T1135 | Discovery |
| netloggedon | T1033 | Discovery |
| tasklist | T1057 | Discovery |
| schtasksquery | T1053.005, T1518 | Persistence / Discovery |
| reg-query | T1012 | Discovery |
| windowlist | T1010 | Discovery |
| routeprint | T1016 | Discovery |
| ldapsearch | T1087.002, T1018 | Discovery |
| nonpaged-ldapsearch | T1087.002 | Discovery |
| adcs-enum-com | T1518.001 | Discovery |
| list-firewall | T1518.001 | Discovery |
| enum-filter-driver | T1518.001, T1014 | Discovery |
| wmi-query | T1047 | Execution |
| get-dpapi-system | T1555.004 | Credential Access |
| clipboard | T1115 | Collection |
| dnscache | T1016.001 | Discovery |
| driversigs | T1518.001 | Discovery |
| findmodule | T1057 | Discovery |
| sccm-decrypt | T1555 | Credential Access |
| ldapsec-check | T1518 | Discovery |

## Phase 3 — Remote Operations (18 BOFs)
| BOF | Techniques | Tactic |
|---|---|---|
| portscan | T1046 | Discovery |
| etw-patch | T1562.006 | Defense Evasion |
| amsi-patch | T1562.001 | Defense Evasion |
| enablepriv | T1134.002 | Privilege Escalation |
| procdump | T1003.001 | Credential Access |
| ghost-task | T1053.005 | Persistence |
| reg-save | T1003.002, T1012 | Credential Access |
| sc-create | T1543.003 | Persistence |
| sc-delete | T1489 | Impact |
| adduser | T1136.001 | Persistence |
| make-token | T1134.003 | Privilege Escalation |
| shspawnas | T1134.002 | Privilege Escalation |
| suspendresume | T1055 | Defense Evasion |
| global-unprotect | T1555.003 | Credential Access |
| inject-crt | T1055.002 | Defense Evasion |
| inject-ntcreate | T1055 | Defense Evasion |
| inject-apc | T1055.004 | Defense Evasion |
| inject-ktable | T1055 | Defense Evasion |

## Phase 4 — OperatorsKit (12 BOFs)
| BOF | Techniques | Tactic |
|---|---|---|
| inject-poolparty | T1055, T1055.012 | Defense Evasion |
| execute-crosssession | T1021.003 | Lateral Movement |
| dcom-localserver32 | T1021.003 | Lateral Movement |
| keylogger-rawinput | T1056.001 | Collection |
| enum-sec-products | T1518.001 | Discovery |
| enum-sysmon | T1518.001 | Discovery |
| spn | T1558.003 | Credential Access |
| wifi-passwords | T1555 | Credential Access |
| cred-prompt | T1056.002 | Collection |
| add-exclusion | T1562.001 | Defense Evasion |
| capture-netntlm | T1187 | Credential Access |
| authenticate-http | T1187 | Credential Access |

## Phase 4 — C2-Collection (8 BOFs)
| BOF | Techniques | Tactic |
|---|---|---|
| psx | T1057, T1134 | Discovery |
| psk | T1518.001, T1057 | Discovery |
| psm | T1057, T1016 | Discovery |
| findobjects | T1057 | Discovery |
| kerberoast | T1558.003 | Credential Access |
| lapsdump | T1555 | Credential Access |
| wdtoggle | T1003.001, T1112 | Defense Evasion |
| cve-2022-26923 | T1068 | Privilege Escalation |

## Phase 5 — Persistence (2 BOFs, original)
| BOF | Techniques | Tactic |
|---|---|---|
| schtask-com | T1053.005 | Persistence |
| lnk-startup | T1547.001 | Persistence |

## Phase 6 — Loader
| Tool | Purpose |
|---|---|
| bofx (inline-execute-ex-opsec) | OPSEC-hardened BOF loader (vendored fork) |

## Phase 11 — Additional SA + Remote-Ops (7 BOFs)
| BOF | Techniques | Tactic |
|---|---|---|
| firewall-rule | T1562.004 | Defense Evasion |
| ai-surface | T1518 | Discovery |
| amsi-etw-detect | T1518.001 | Discovery |
| bitlocker-status | T1486, T1005 | Impact / Collection |
| ide-extension-surface | T1518 | Discovery |
| proxy-enum | T1016 | Discovery |
| wevt-logon-enum | T1087.001 | Discovery |

