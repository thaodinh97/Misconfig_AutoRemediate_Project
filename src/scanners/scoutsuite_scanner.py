
import json
import logging
import subprocess
import shutil
from typing import List, Dict, Any
from uuid import uuid4

from . import BaseScanner
from ..models import NormalizedFinding, SeverityLevel

logger = logging.getLogger(__name__)


class ScoutSuiteScanner(BaseScanner):
    """ScoutSuite scanner for multi-cloud findings"""
    
    def __init__(self, provider: str = "aws", profile: str = None, region: str = None):
        super().__init__(provider, region)
        self.profile = profile or "default"
        self.report_dir = f"/tmp/scout-{self.scan_id}"
    
    def run(self) -> List[Dict[str, Any]]:
        """Execute ScoutSuite scan"""
        try:
            # Check if scoutsuite command exists
            if not shutil.which("scoutsuite"):
                logger.warning("ScoutSuite command not found. Install with: pip install scoutsuite[reports]")
                return []
            
            cmd = ["scoutsuite", "--report-dir", self.report_dir]
            
            if self.provider == "aws":
                cmd.extend(["--profile", self.profile, "--regions", self.region])
            elif self.provider == "azure":
                cmd.append("--cli")  
            
            logger.info(f"Running ScoutSuite command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.error(f"ScoutSuite failed: {result.stderr}")
                return []
            
            # Read the generated report
            report_file = f"{self.report_dir}/scoutsuite-report.json"
            with open(report_file, 'r') as f:
                report = json.load(f)
            
            return self._extract_findings(report)
        
        except FileNotFoundError:
            logger.warning("ScoutSuite binary not found. Skipping ScoutSuite scan.")
            return []
        except Exception as e:
            logger.error(f"ScoutSuite execution error: {str(e)}")
            return []
    
    def _extract_findings(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from ScoutSuite report"""
        findings = []
        
        if 'services' in report:
            for service, service_data in report['services'].items():
                findings.extend(self._process_service(service, service_data))
        
        return findings
    
    def _process_service(self, service: str, service_data: Dict) -> List[Dict]:
        """Process findings for a specific service"""
        findings = []
        
        for finding_type, finding_data in service_data.items():
            if isinstance(finding_data, dict) and 'issues' in finding_data:
                for issue in finding_data['issues']:
                    findings.append({
                        'service': service,
                        'finding_type': finding_type,
                        'issue': issue,
                    })
        
        return findings
    
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """Normalize ScoutSuite findings"""
        normalized = []
        
        for raw in raw_findings:
            try:
                finding = NormalizedFinding(
                    finding_id=str(uuid4()),
                    finding_code=f"SCOUT-{raw.get('service', 'unknown').upper()}",
                    scanner="scoutsuite",
                    provider=self.provider,
                    severity=self._get_severity(raw),
                    title=raw.get('issue', {}).get('description', 'Unknown finding'),
                    description=raw.get('issue', {}).get('description', ''),
                    resource_type=raw.get('service', 'unknown'),
                    resource_id=str(raw.get('issue', {}).get('resource_id', 'unknown')),
                    region=self.region,
                    remediation_available=True,
                    remediation_type="cloud_custodian",
                    metadata={
                        'raw_issue': raw.get('issue', {}).get('level', 3),
                    }
                )
                normalized.append(finding)
            except Exception as e:
                logger.warning(f"Failed to normalize ScoutSuite finding: {str(e)}")
        
        return normalized
    
    @staticmethod
    def _get_severity(raw_finding: Dict) -> SeverityLevel:
        """Map ScoutSuite severity to normalized level"""
        issue_level = raw_finding.get('issue', {}).get('level', 2)
        # ScoutSuite: 1=critical, 2=high, 3=medium
        level_map = {
            1: SeverityLevel.CRITICAL,
            2: SeverityLevel.HIGH,
            3: SeverityLevel.MEDIUM,
        }
        return level_map.get(issue_level, SeverityLevel.MEDIUM)
