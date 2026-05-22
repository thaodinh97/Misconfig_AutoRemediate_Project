import logging
from typing import List, Dict, Any
from ..models import SeverityLevel, NormalizedFinding, TriageDecision, StatusEnum

logger = logging.getLogger(__name__)

class TriageEngine:
    """
    Triage Engine for remediation decision making
    
    Analyzes findings and makes decisions on:
    - Whether to auto-remediate
    - Whether to escalate for manual review
    - Confidence scores for each decision
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.auto_remediate_threshold = self.config.get('auto_remediate_threshold', 'MEDIUM')
        self.high_risk_resources = self.config.get('high_risk_resources', ['prod', 'production', 'critical'])
        self.manual_review_severity = self.config.get('manual_review_severity', 'HIGH')
        self.remediation_blacklist = self.config.get('remediation_blacklist', [])

    def triage_finding(self, finding: NormalizedFinding) -> TriageDecision:
        """Make a triage decision for a single finding"""
        
        # Determine if this finding should be auto-remediated
        is_auto = self._is_auto_remediate(finding)
        
        if is_auto:
            recommendation = "auto_remediate"
            confidence = self._calculate_auto_confidence(finding)
        else:
            recommendation = "manual_review"
            confidence = self._calculate_manual_confidence(finding)
        
        reasoning = self._generate_reasoning(finding, recommendation)
        
        return TriageDecision(
            finding_id=finding.finding_id,
            recommendation=recommendation,
            confidence_score=confidence,
            reasoning=reasoning,
            metadata={
                'severity': finding.severity,
                'resource_type': finding.resource_type,
                'resource_id': finding.resource_id,
                'remediation_available': finding.remediation_available,
                'scanner': finding.scanner,
                'finding_code': finding.finding_code,
            }
        )
    
    def triage_batch(self, findings: List[NormalizedFinding]) -> List[TriageDecision]:
        """Triage multiple findings"""
        decisions = []
        for finding in findings:
            try:
                decision = self.triage_finding(finding=finding)
                decisions.append(decision)
            except Exception as e:
                logger.error(f"Error triaging finding {finding.finding_id}: {str(e)}")
        return decisions
    
    def _is_auto_remediate(self, finding: NormalizedFinding) -> bool:
        """Determine if a finding should be auto-remediated"""
        
        # Must have remediation available
        if not finding.remediation_available:
            logger.debug(f"Finding {finding.finding_id}: remediation not available")
            return False
        
        # Blacklist check
        for pattern in self.remediation_blacklist:
            if pattern.lower() in finding.finding_code.lower():
                logger.debug(f"Finding {finding.finding_id}: blacklisted")
                return False
        
        # Severity check - don't auto-remediate if severity is above threshold
        if self._severity_level(finding.severity) > self._severity_level(self.auto_remediate_threshold):
            logger.debug(
                f"Finding {finding.finding_id}: severity {finding.severity} "
                f"exceeds threshold {self.auto_remediate_threshold}"
            )
            return False
        
        # High-risk resource check
        environment = finding.metadata.get('environment', '').lower()
        for risk_pattern in self.high_risk_resources:
            if risk_pattern.lower() in environment:
                logger.debug(f"Finding {finding.finding_id}: high-risk resource")
                return False
        
        # Already remediated or false positive
        if finding.status in [StatusEnum.REMEDIATED, StatusEnum.FALSE_POSITIVE]:
            logger.debug(f"Finding {finding.finding_id}: already processed")
            return False
        
        # False positive detection
        if self._is_likely_false_positive(finding):
            logger.debug(f"Finding {finding.finding_id}: likely false positive")
            return False
        
        logger.debug(f"Finding {finding.finding_id}: eligible for auto-remediation")
        return True
    
    def _is_likely_false_positive(self, finding: NormalizedFinding) -> bool:
        """Detect likely false positives"""
        
        # Known false positive patterns
        false_positive_patterns = {
            'scoutsuite': [
                'cloudtrail_cloudwatch_logging_enabled',
                'cloudtrail_log_file_validation',
            ],
            'checkov': [
                'CK_CUSTOM_',
            ],
            'cloudsploit': [],
        }
        
        scanner = finding.scanner.lower()
        code = finding.finding_code.lower()
        
        if scanner in false_positive_patterns:
            for pattern in false_positive_patterns[scanner]:
                if pattern.lower() in code:
                    return True
        
        # Check for whitelisted resources in description
        if 'test' in finding.resource_id.lower() or 'dev' in finding.resource_id.lower():
            return False  # Don't skip test/dev resources
        
        return False
    
    def _calculate_auto_confidence(self, finding: NormalizedFinding) -> float:
        """Calculate confidence score for auto-remediation"""
        
        base_confidence = 0.85
        
        # Adjust based on severity
        if finding.severity == SeverityLevel.LOW:
            base_confidence += 0.1
        elif finding.severity == SeverityLevel.CRITICAL:
            base_confidence -= 0.2
        
        # Adjust based on scanner
        scanner_confidence = {
            'checkov': 0.9,
            'scoutsuite': 0.8,
            'cloudsploit': 0.75,
        }
        
        scanner_factor = scanner_confidence.get(finding.scanner.lower(), 0.8)
        base_confidence = (base_confidence + scanner_factor) / 2
        
        # Clamp between 0.5 and 1.0
        return min(1.0, max(0.5, base_confidence))
    
    def _calculate_manual_confidence(self, finding: NormalizedFinding) -> float:
        """Calculate confidence score for manual review"""
        
        base_confidence = 0.9
        
        # Higher confidence if severity is high
        if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            base_confidence = 0.95
        
        # Lower confidence if remediation is available (might miss something)
        if finding.remediation_available:
            base_confidence -= 0.05
        
        return min(1.0, max(0.5, base_confidence))
    
    @staticmethod
    def _severity_level(severity: SeverityLevel) -> int:
        """Map severity to numeric level for comparison"""
        level_map = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
        }
        if isinstance(severity, str):
            try:
                severity = SeverityLevel(severity)
            except (ValueError, KeyError):
                return 3  # Default to MEDIUM
        return level_map.get(severity, 3)
    
    @staticmethod
    def _generate_reasoning(finding: NormalizedFinding, recommendation: str) -> str:
        """Generate human-readable reasoning for the decision"""
        parts = [
            f"Severity: {finding.severity}",
            f"Resource: {finding.resource_type}/{finding.resource_id}",
            f"Scanner: {finding.scanner}",
            f"Available: {'Yes' if finding.remediation_available else 'No'}",
        ]
        
        if recommendation == "auto_remediate":
            parts.append("Decision: Automatically remediate based on severity and availability")
        elif recommendation == "manual_review":
            reasons = []
            if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                reasons.append("high severity requires approval")
            if not finding.remediation_available:
                reasons.append("remediation not fully automated")
            if not reasons:
                reasons.append("manual review recommended")
            
            parts.append(f"Decision: Manual review needed ({', '.join(reasons)})")
        
        return "; ".join(parts)
    
    def get_summary(self, decisions: List[TriageDecision]) -> Dict[str, Any]:
        """Get summary statistics for triage decisions"""
        
        auto_remediate_count = sum(1 for d in decisions if d.recommendation == "auto_remediate")
        manual_review_count = sum(1 for d in decisions if d.recommendation == "manual_review")
        ignore_count = sum(1 for d in decisions if d.recommendation == "ignore")
        
        avg_confidence = sum(d.confidence_score for d in decisions) / len(decisions) if decisions else 0
        
        return {
            'total_decisions': len(decisions),
            'auto_remediate': auto_remediate_count,
            'auto_remediate_percentage': (auto_remediate_count / len(decisions) * 100) if decisions else 0,
            'manual_review': manual_review_count,
            'manual_review_percentage': (manual_review_count / len(decisions) * 100) if decisions else 0,
            'ignore': ignore_count,
            'avg_confidence_score': round(avg_confidence, 3),
            'min_confidence_score': round(min((d.confidence_score for d in decisions), default=0), 3),
            'max_confidence_score': round(max((d.confidence_score for d in decisions), default=0), 3),
        }