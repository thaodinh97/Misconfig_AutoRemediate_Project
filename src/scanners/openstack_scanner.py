"""
OpenStack live infrastructure scanner
Scans live OpenStack cloud for misconfigurations
"""
from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Dict, List
from uuid import uuid4, uuid5, NAMESPACE_URL

from . import BaseScanner
from ..models import NormalizedFinding, SeverityLevel

logger = logging.getLogger(__name__)


class OpenStackScanner(BaseScanner):
    """Live OpenStack scanner for cloud misconfigurations"""

    def __init__(self, project_prefix: str = "threat-demo"):
        super().__init__("openstack", region=None)
        self.project_prefix = project_prefix
        self.public_container = f"{project_prefix}-m1-public-container"
        self.wide_open_sg = f"{project_prefix}-m2-wide-open-sg"
        self.demo_project = f"{project_prefix}-m3-overpriv-project"
        self.demo_user = f"{project_prefix}-m3-overpriv-user"

    def _run_openstack_cmd(self, cmd: List[str]) -> Dict[str, Any]:
        """Execute OpenStack CLI command and return JSON output"""
        full_cmd = ["openstack"] + cmd + ["-f", "json"]
        
        try:
            logger.info(f"Running OpenStack command: {' '.join(full_cmd)}")
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False
            )
            
            if result.returncode != 0:
                logger.warning(f"OpenStack command failed: {result.stderr}")
                return {}
            
            if not result.stdout.strip():
                return {}
            
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OpenStack JSON output: {str(e)}")
            return {}
        except Exception as e:
            logger.error(f"OpenStack command execution error: {str(e)}")
            return {}

    def run(self) -> List[Dict[str, Any]]:
        """Execute OpenStack scan"""
        raw_findings = []
        
        # Scan 1: Swift public container
        logger.info(f"Scanning Swift container: {self.public_container}")
        container_data = self._run_openstack_cmd(
            ["container", "show", self.public_container]
        )
        if container_data:
            raw_findings.extend(self._check_public_container(container_data))
        
        # Scan 2: Security group rules
        logger.info(f"Scanning security group: {self.wide_open_sg}")
        sg_rules = self._run_openstack_cmd(
            ["security", "group", "rule", "list", self.wide_open_sg]
        )
        if isinstance(sg_rules, list):
            raw_findings.extend(self._check_security_group_rules(sg_rules))
        
        # Scan 3: IAM role assignments
        logger.info(f"Scanning role assignments for project: {self.demo_project}")
        role_assignments = self._run_openstack_cmd(
            ["role", "assignment", "list", "--project", self.demo_project,
             "--user", self.demo_user, "--names"]
        )
        if isinstance(role_assignments, list):
            raw_findings.extend(self._check_role_assignments(role_assignments))
        
        logger.info(f"OpenStack scan completed: {len(raw_findings)} findings")
        return raw_findings

    def _check_public_container(self, container: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for public Swift containers"""
        findings = []
        
        read_acl = str(container.get("read_ACL", container.get("read_acl", "")))
        is_public = ".r:*" in read_acl or ".rlistings" in read_acl
        
        if is_public:
            container_name = container.get("name", container.get("container", "unknown"))
            findings.append({
                "code": "OPENSTACK_SWIFT_PUBLIC_READ",
                "severity": "HIGH",
                "title": "OpenStack Swift container allows public read",
                "description": f"Container {container_name} exposes public read/listing ACLs via {read_acl}",
                "resource_type": "swift_container",
                "resource_id": container_name,
                "resource_name": container_name,
                "metadata": {
                    "read_acl": read_acl,
                    "write_acl": container.get("write_ACL", container.get("write_acl", ""))
                }
            })
        
        return findings

    def _check_security_group_rules(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for wide-open security group rules"""
        findings = []
        
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            
            cidr = rule.get("CIDR", rule.get("cidr", "0.0.0.0/0"))
            remote_group = rule.get("remote_group_id", rule.get("Remote Group"))
            port_range_min = rule.get("port_range_min")
            port_range_max = rule.get("port_range_max")
            
            # Check if rule is wide open (0.0.0.0/0)
            if cidr == "0.0.0.0/0" and not remote_group:
                protocol = rule.get("IP Protocol", rule.get("protocol", "")).lower()
                port_info = ""
                
                if port_range_min and port_range_max:
                    if port_range_min == port_range_max:
                        port_info = f"port {port_range_min}"
                    else:
                        port_info = f"ports {port_range_min}-{port_range_max}"
                elif port_range_min:
                    port_info = f"port {port_range_min}"
                
                if protocol == "-1" or not protocol:
                    protocol_desc = "all protocols"
                else:
                    protocol_desc = f"{protocol} {port_info}".strip()
                
                findings.append({
                    "code": "OPENSTACK_SG_WIDE_OPEN",
                    "severity": "CRITICAL",
                    "title": "OpenStack security group allows unrestricted access",
                    "description": f"Security group allows {protocol_desc} from 0.0.0.0/0 (world-accessible)",
                    "resource_type": "security_group_rule",
                    "resource_id": rule.get("ID", rule.get("id", str(uuid4()))),
                    "resource_name": self.wide_open_sg,
                    "metadata": {
                        "cidr": cidr,
                        "protocol": protocol,
                        "port_range_min": port_range_min,
                        "port_range_max": port_range_max
                    }
                })
        
        return findings

    def _check_role_assignments(self, assignments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for overprivileged role assignments"""
        findings = []
        
        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            
            role_name = assignment.get("Role", assignment.get("role", ""))
            
            # Check for admin role
            if role_name.lower() == "admin" or "admin" in str(role_name).lower():
                user_name = assignment.get("User", assignment.get("user", self.demo_user))
                project_name = assignment.get("Project", assignment.get("project", self.demo_project))
                
                findings.append({
                    "code": "OPENSTACK_PROJECT_ADMIN_ASSIGNMENT",
                    "severity": "HIGH",
                    "title": "OpenStack user has admin role on project",
                    "description": f"User {user_name} has admin role on project {project_name}, which is overprivileged",
                    "resource_type": "role_assignment",
                    "resource_id": f"{project_name}:{user_name}",
                    "resource_name": f"{user_name}@{project_name}",
                    "metadata": {
                        "user": user_name,
                        "project": project_name,
                        "role": role_name
                    }
                })
        
        return findings

    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """Normalize OpenStack findings to standard format"""
        normalized = []
        
        for raw in raw_findings:
            try:
                code = raw.get("code", "UNKNOWN")
                severity_str = raw.get("severity", "MEDIUM").upper()
                
                severity_map = {
                    "CRITICAL": SeverityLevel.CRITICAL,
                    "HIGH": SeverityLevel.HIGH,
                    "MEDIUM": SeverityLevel.MEDIUM,
                    "LOW": SeverityLevel.LOW,
                    "INFO": SeverityLevel.INFO,
                }
                severity = severity_map.get(severity_str, SeverityLevel.MEDIUM)
                
                resource_id = raw.get("resource_id", "")
                discriminator = json.dumps(raw.get("metadata", {}), sort_keys=True, default=str)
                finding_id = str(uuid5(NAMESPACE_URL, f"openstack:{code}:{resource_id}:{discriminator}"))
                
                finding = NormalizedFinding(
                    finding_id=finding_id,
                    finding_code=code,
                    scanner="openstack",
                    provider="openstack",
                    severity=severity,
                    title=raw.get("title", "OpenStack finding"),
                    description=raw.get("description", ""),
                    resource_type=raw.get("resource_type", "openstack_resource"),
                    resource_id=resource_id,
                    resource_name=raw.get("resource_name", resource_id),
                    region=None,
                    risk_category="misconfiguration",
                    remediation_available=True,
                    remediation_type="ansible",
                    metadata=raw.get("metadata", {})
                )
                normalized.append(finding)
                
            except Exception as e:
                logger.warning(f"Failed to normalize OpenStack finding: {str(e)}")
        
        return normalized
