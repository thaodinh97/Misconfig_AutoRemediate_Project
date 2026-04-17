"""
CloudSploit scanner integration
"""
import json
import logging
import os
import shutil
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
    
    def _get_cloudsploit_command(self) -> str:
        """Find CloudSploit executable path or use npx"""
        # Try to find cloudsploit in PATH
        cloudsploit_path = shutil.which("cloudsploit")
        if cloudsploit_path:
            return cloudsploit_path
        
        # Try npx (requires Node.js to be installed)
        npx_path = shutil.which("npx")
        if npx_path:
            logger.info("Using npx to run CloudSploit")
            return "npx"
        
        logger.warning("CloudSploit command not found. Install with: npm install -g cloudsploit")
        return None
    
    def run(self) -> List[Dict[str, Any]]:
        try:
            cloudsploit_cmd = self._get_cloudsploit_command()
            if not cloudsploit_cmd:
                logger.warning("CloudSploit not available, skipping scan")
                return []
            
            # Build command - if using npx, add 'cloudsploit' as first argument
            if cloudsploit_cmd == "npx":
                cmd = ["npx", "cloudsploit", "scan", "--json"]
            else:
                cmd = [cloudsploit_cmd, "scan", "--json"]

            logger.info(f"Running CloudSploit command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode != 0:
                logger.error(f"CloudSploit failed: {result.stderr}")
                return []

            # ⚠️ Parse JSON safely
            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.error("Invalid JSON output from CloudSploit")
                logger.error(f"CloudSploit stdout: {result.stdout}")
                logger.error(f"CloudSploit stderr: {result.stderr}")
                if result.stderr:
                    try:
                        report = json.loads(result.stderr)
                        return self._extract_findings(report)
                    except json.JSONDecodeError:
                        pass
                return []

            return self._extract_findings(report)

        except Exception as e:
            logger.error(f"CloudSploit execution error: {str(e)}")
            return []
    
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
