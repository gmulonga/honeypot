from stix2 import Bundle, Indicator, AttackPattern, Relationship, Identity, ThreatActor
from stix2.v21 import ObservedData, IPv4Address
from datetime import datetime
from typing import List, Dict, Any
import json
import logging

logger = logging.getLogger(__name__)

class STIXGenerator:
    def __init__(self, analysis_data: Dict[str, Any] = None, processed_logs: List[Dict] = None):
        self.analysis_data = analysis_data or {}
        self.processed_logs = processed_logs or []
        self.bundle_objects = []
        
        # Create organization identity
        self.organization = Identity(
            name="Kenyan Cloud Security Team",
            identity_class="organization",
            sectors=["technology", "security"],
            contact_information="security@kenyancloud.ke"
        )
        self.bundle_objects.append(self.organization)
    
    def generate_bundle(self) -> Dict[str, Any]:
        """Generate STIX 2.1 bundle from analysis data"""
        
        try:
            # Use processed_logs if available, otherwise use attacks from analysis_data
            if self.processed_logs:
                attacks = self.processed_logs
            else:
                # Try to get attacks from different possible keys
                attacks = self.analysis_data.get('attacks', [])
                if not attacks:
                    attacks = self.analysis_data.get('processed_data', [])
                if not attacks:
                    attacks = self.analysis_data.get('logs', [])
            
            logger.info(f"Generating STIX bundle from {len(attacks)} attacks")
            
            # Create indicators from attacks
            attack_count = 0
            for attack in attacks[:100]:  # Limit for performance
                try:
                    if isinstance(attack, dict):
                        indicator = self._create_indicator(attack)
                        if indicator:
                            self.bundle_objects.append(indicator)
                            attack_count += 1
                except Exception as e:
                    logger.warning(f"Failed to create indicator for attack: {e}")
                    continue
            
            logger.info(f"Created {attack_count} indicators")
            
            # Create MITRE ATT&CK patterns
            techniques = self.analysis_data.get('mitre_techniques', {})
            if not isinstance(techniques, dict):
                techniques = {}
            
            technique_count = 0
            for technique_id, count in techniques.items():
                try:
                    if count and int(count) > 0:
                        attack_pattern = self._create_attack_pattern(technique_id, int(count))
                        if attack_pattern:
                            self.bundle_objects.append(attack_pattern)
                            technique_count += 1
                except Exception as e:
                    logger.warning(f"Failed to create attack pattern for {technique_id}: {e}")
                    continue
            
            logger.info(f"Created {technique_count} attack patterns")
            
            # Create relationships
            relationship_count = self._create_relationships()
            logger.info(f"Created {relationship_count} relationships")
            
            # Create bundle
            if len(self.bundle_objects) > 1:  # More than just the identity
                bundle = Bundle(objects=self.bundle_objects)
                result = json.loads(bundle.serialize())
                logger.info(f"STIX bundle generated with {len(self.bundle_objects)} objects")
                return result
            else:
                logger.warning("No STIX objects created, returning empty bundle")
                return self._create_empty_bundle()
            
        except Exception as e:
            logger.error(f"Error generating STIX bundle: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return self._create_empty_bundle()
    
    def _create_empty_bundle(self) -> Dict[str, Any]:
        """Create empty STIX bundle with just identity"""
        bundle = Bundle(objects=[self.organization])
        return json.loads(bundle.serialize())
    
    def _create_indicator(self, attack: Dict) -> Indicator:
        """Create STIX Indicator from attack data"""
        try:
            # Extract data from attack
            source_ip = attack.get('source_ip', 'unknown')
            attack_type = attack.get('attack_type', 'unknown')
            port = attack.get('port', 'unknown')
            
            # Parse timestamp
            timestamp = attack.get('timestamp')
            if not timestamp:
                timestamp = datetime.now()
            elif not isinstance(timestamp, datetime):
                try:
                    if isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    else:
                        timestamp = datetime.now()
                except:
                    timestamp = datetime.now()
            
            # Create pattern
            pattern = self._create_pattern(attack)
            
            # Create description
            description = f"{attack_type} attack"
            if source_ip != 'unknown':
                description += f" from {source_ip}"
            if port and port != 'unknown':
                description += f" on port {port}"
            
            return Indicator(
                name=f"Attack from {source_ip}",
                description=description,
                pattern=pattern,
                pattern_type="stix",
                valid_from=timestamp,
                labels=[attack_type if attack_type else "malicious-activity"],
                created_by_ref=self.organization.id
            )
        except Exception as e:
            logger.warning(f"Failed to create indicator: {e}")
            return None
    
    def _create_pattern(self, attack: Dict) -> str:
        """Create STIX pattern for attack"""
        try:
            ip = attack.get('source_ip', '')
            port = attack.get('port', '')
            
            if ip and ip != 'unknown' and port and port != 'unknown':
                return f"[ipv4-addr:value = '{ip}' AND network-traffic:dst_port = '{port}']"
            elif ip and ip != 'unknown':
                return f"[ipv4-addr:value = '{ip}']"
            else:
                return "[malicious-activity:value = 'suspicious']"
        except:
            return "[malicious-activity:value = 'suspicious']"
    
    def _create_attack_pattern(self, technique_id: str, count: int) -> AttackPattern:
        """Create MITRE ATT&CK Attack Pattern"""
        try:
            technique_name = self._get_technique_name(technique_id)
            
            return AttackPattern(
                name=technique_name,
                description=f"MITRE ATT&CK Technique {technique_id} - Observed {count} times",
                kill_chain_phases=[{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": self._get_phase_from_technique(technique_id)
                }],
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                }],
                created_by_ref=self.organization.id
            )
        except Exception as e:
            logger.warning(f"Failed to create attack pattern: {e}")
            return None
    
    def _get_technique_name(self, technique_id: str) -> str:
        """Map MITRE technique ID to name"""
        techniques = {
            "T1110": "Brute Force",
            "T1046": "Network Service Scanning",
            "T1204": "User Execution",
            "T1498": "Network Denial of Service",
            "T1210": "Exploitation of Remote Services",
            "T1566": "Phishing",
            "T1078": "Valid Accounts",
            "T1059": "Command and Scripting Interpreter",
            "T1105": "Ingress Tool Transfer",
            "T1485": "Data Destruction",
            "T1041": "Exfiltration Over C2 Channel",
            "T1190": "Exploit Public-Facing Application",
            "T1040": "Network Sniffing"
        }
        return techniques.get(technique_id, f"Technique {technique_id}")
    
    def _get_phase_from_technique(self, technique_id: str) -> str:
        """Get phase name from technique ID"""
        # Simple mapping - you can expand this
        if technique_id.startswith('T1'):  # Typically initial access, execution
            return "initial-access"
        elif technique_id.startswith('T2'):  # Typically privilege escalation
            return "privilege-escalation"
        elif technique_id.startswith('T10'):  # Typically discovery, lateral movement
            return "lateral-movement"
        else:
            return "execution"
    
    def _create_relationships(self) -> int:
        """Create relationships between STIX objects"""
        relationship_count = 0
        
        try:
            # Create relationships between indicators and attack patterns
            indicators = [obj for obj in self.bundle_objects if hasattr(obj, 'type') and obj.type == 'indicator']
            attack_patterns = [obj for obj in self.bundle_objects if hasattr(obj, 'type') and obj.type == 'attack-pattern']
            
            # Each indicator relates to the organization
            for indicator in indicators:
                try:
                    relationship = Relationship(
                        relationship_type='indicates',
                        source_ref=indicator.id,
                        target_ref=self.organization.id,
                        description='Potential threat to organization'
                    )
                    self.bundle_objects.append(relationship)
                    relationship_count += 1
                except Exception as e:
                    logger.warning(f"Failed to create relationship: {e}")
                    continue
            
            return relationship_count
        except Exception as e:
            logger.warning(f"Error creating relationships: {e}")
            return 0
    
    def generate_report_file(self, filepath: str = "stix_report.json") -> str:
        """Generate and save STIX report to file"""
        
        bundle = self.generate_bundle()
        
        with open(filepath, 'w') as f:
            json.dump(bundle, f, indent=2, default=str)
        
        return filepath
    
    async def generate_for_attacks(self, attack_ids: List[str]) -> Dict[str, Any]:
        """Generate STIX for specific attacks"""
        # Filter processed logs by attack_ids if needed
        filtered_attacks = []
        if self.processed_logs and attack_ids:
            # This is a simple filter - you might need to match by actual attack IDs
            filtered_attacks = [attack for attack in self.processed_logs[:10]]
        
        # Create a temporary generator with filtered attacks
        temp_generator = STIXGenerator(processed_logs=filtered_attacks)
        return temp_generator.generate_bundle()