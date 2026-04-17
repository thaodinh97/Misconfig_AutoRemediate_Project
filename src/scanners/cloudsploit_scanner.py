"""
CloudSploit scanner integration
"""
import json
import logging
import os
import subprocess
from typing import List, Dict, Any
from uuid import uuid4

from . import BaseScanner
from ..models import NormalizedFinding, SeverityLevel

logger = logging.getLogger(__name__)


class CloudsploitScanner(BaseScanner):
    """CloudSploit scanner for AWS findings"""
    
    def __init__(self, profile: str = "default", region: str = "us-east-1"):
        super().__init__("aws", region)
        self.profile = profile
        self.config_file = f"/tmp/cloudsploit-{self.scan_id}.json"
    
    def run(self) -> List[Dict[str, Any]]:
        """Execute CloudSploit scan"""
        try:
            with open(self.config_file, "w") as f:
                json.dump({}, f)

            aws_dir = os.path.expanduser("~/.aws")

            cmd = [
                "docker", "run", "--rm",
                "-e", f"AWS_PROFILE={self.profile}",
                "-v", f"{self.config_file}:/app/config.json",
                "cloudsploit/scanner",
                "--config", "/app/config.json",
                "--output", "json",
            ]

            if os.path.isdir(aws_dir):
                cmd[5:5] = ["-v", f"{aws_dir}:/root/.aws:ro"]
            
            logger.info(f"Running CloudSploit command")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.error(f"CloudSploit failed: {result.stderr}")
                return []
            
            output = result.stdout
            report = json.loads(output)
            return self._extract_findings(report)
        
        except Exception as e:
            logger.error(f"CloudSploit execution error: {str(e)}")
            raise
    
    def _extract_findings(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from CloudSploit report"""
        findings = []
        
        for plugin, plugin_data in report.items():
            if isinstance(plugin_data, dict):
                for region, region_data in plugin_data.items():
                    if isinstance(region_data, dict):
                        for result in region_data.get('results', []):
                            findings.append({
                                'plugin': plugin,
                                'region': region,
                                'result': result,
                            })
        
        return findings
    
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """Normalize CloudSploit findings"""
        normalized = []
        
        for raw in raw_findings:
            try:
                result = raw.get('result', {})
                plugin = raw.get('plugin', 'unknown')
                
                # CloudSploit result format: {status: 'FAIL', message: '...', region: '...'}
                if result.get('status') != 'FAIL':
                    continue
                
                finding = NormalizedFinding(
                    finding_id=str(uuid4()),
                    finding_code=f"CS-{plugin.upper()}",
                    scanner="cloudsploit",
                    provider="aws",
                    severity=self.map_severity(result.get('severity', 'medium')),
                    title=f"{plugin}: {result.get('message', 'No message')}",
                    description=result.get('message', ''),
                    resource_type=plugin,
                    resource_id=result.get('resource_id', 'unknown'),
                    region=raw.get('region', self.region),
                    remediation_available=True,
                    remediation_type="cloud_custodian",
                    metadata={
                        'plugin': plugin,
                        'region': raw.get('region'),
                        'status': result.get('status'),
                    }
                )
                normalized.append(finding)
            except Exception as e:
                logger.warning(f"Failed to normalize CloudSploit finding: {str(e)}")
        
        return normalized
