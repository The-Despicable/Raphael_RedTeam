import logging, re, time, uuid
from dataclasses import dataclass, field
from typing import Optional

from orchestrator.agents.base import GoalType, Task, TaskStatus

logger = logging.getLogger("goal_tree")


@dataclass
class GoalNode:
    type: GoalType
    target: str
    status: TaskStatus = TaskStatus.PENDING
    description: str = ""
    findings: list = field(default_factory=list)
    children: list["GoalNode"] = field(default_factory=list)
    parent: Optional["GoalNode"] = None
    error: str = ""
    created_at: float = 0.0

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "target": self.target,
            "status": self.status.value,
            "description": self.description,
            "findings_count": len(self.findings),
            "children": [c.to_dict() for c in self.children],
            "error": self.error,
        }

    def add_child(self, child: "GoalNode"):
        child.parent = self
        self.children.append(child)

    def leaves(self) -> list["GoalNode"]:
        if not self.children:
            return [self]
        result = []
        for c in self.children:
            result.extend(c.leaves())
        return result

    def all_nodes(self) -> list["GoalNode"]:
        nodes = [self]
        for c in self.children:
            nodes.extend(c.all_nodes())
        return nodes


@dataclass
class GoalTree:
    root: GoalNode
    engagement_id: str = ""
    created_at: float = 0.0

    def __post_init__(self):
        if not self.created_at:
            self.created_at = time.time()
        if not self.engagement_id:
            self.engagement_id = uuid.uuid4().hex[:12]

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.engagement_id,
            "root": self.root.to_dict(),
            "created_at": self.created_at,
        }

    def leaves(self) -> list[GoalNode]:
        return self.root.leaves()

    def all_nodes(self) -> list[GoalNode]:
        return self.root.all_nodes()

    def is_complete(self) -> bool:
        for n in self.all_nodes():
            if n.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                return False
        return True


DESTRUCTIVE_PATTERNS = [
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=/dev/zero\b", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bformat\b", re.IGNORECASE),
    re.compile(r"\bfdisk\b", re.IGNORECASE),
    re.compile(r"\b>:?\s*/dev/\b"),
]

KNOWN_TOOLS = {
    GoalType.RECON: {"nmap", "dns", "whatweb", "subfinder", "gobuster", "curl", "whois"},
    GoalType.SCAN: {"nmap", "nuclei", "nikto", "gobuster", "ffuf", "sqlmap", "sslscan"},
    GoalType.EXPLOIT: {"metasploit", "sqlmap", "hydra", "python", "searchsploit"},
    GoalType.POSTEX: {"sliver", "impacket", "bloodhound", "certipy", "socat"},
    GoalType.LATERAL: {"ssh", "wmiexec", "psexec", "smbexec", "impacket"},
    GoalType.CREDENTIAL: {"hydra", "john", "hashcat", "spray"},
    GoalType.EXFIL: {"curl", "scp", "rsync", "socat"},
    GoalType.PHISH: {"gophish", "sendmail", "smtp"},
    GoalType.REPORT: set(),
}


class GoalValidator:
    def __init__(self, allowed_domains: list[str] = None, allowed_ips: list[str] = None):
        self.allowed_domains = allowed_domains or []
        self.allowed_ips = allowed_ips or []

    def validate_node(self, node: GoalNode) -> tuple[bool, str]:
        if node.type not in GoalType.__members__.values():
            return False, f"Unknown goal type: {node.type}"

        if not node.target:
            return False, "Empty target"

        if self.allowed_domains or self.allowed_ips:
            in_domain = any(d in node.target for d in self.allowed_domains)
            in_ip = any(node.target.startswith(ip.replace("0.0/8", "").replace("0.0.0/8", "").rstrip("."))
                        for ip in self.allowed_ips if "/" not in ip)
            if not in_domain and not in_ip:
                return False, f"Target {node.target} not in allowed scope"

        return True, ""

    def validate_goal_tree(self, tree: GoalTree) -> list[tuple[GoalNode, str]]:
        errors = []
        for node in tree.all_nodes():
            valid, msg = self.validate_node(node)
            if not valid:
                errors.append((node, msg))
        return errors


def recon_sweep(target: str) -> GoalTree:
    root = GoalNode(type=GoalType.RECON, target=target, description=f"Recon sweep of {target}")
    sweep_goals = [
        GoalNode(type=GoalType.RECON, target=target, description="DNS enumeration"),
        GoalNode(type=GoalType.RECON, target=target, description="Port scan (top 1000)"),
        GoalNode(type=GoalType.SCAN, target=target, description="Service version scan"),
    ]
    for g in sweep_goals:
        root.add_child(g)
    return GoalTree(root=root)
