from typing import List, Dict, Any
from datetime import datetime, timedelta
import pandas as pd
from collections import Counter
import geoip2.database
import geoip2.errors
import logging

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    def __init__(self, data: List[Dict] = None):
        self.data = data or []
        self.geoip_reader = None
        
        # Initialize GeoIP database
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except:
            print("GeoIP database not found, proceeding without geolocation")

    async def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive threat analysis"""
        
        if not self.data:
            logger.warning("No data provided for analysis")
            return {}
        
        try:
            # Convert to DataFrame for analysis
            df = pd.DataFrame(self.data)
            
            # Basic statistics
            total_attacks = len(df)
            unique_ips = df['source_ip'].nunique() if 'source_ip' in df.columns else 0
            
            # Attack type distribution
            if 'attack_type' in df.columns:
                attack_dist = df['attack_type'].value_counts().to_dict()
            else:
                attack_dist = {}
            
            # Timeline analysis
            hourly_attacks = {}
            if 'timestamp' in df.columns and len(df) > 0:
                try:
                    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
                    hourly_attacks = df.groupby('hour').size().to_dict()
                except Exception as e:
                    logger.warning(f"Error creating timeline: {e}")
            
            # Severity analysis
            avg_severity = 0
            high_severity = 0
            if 'severity' in df.columns and len(df) > 0:
                avg_severity = df['severity'].mean()
                high_severity = len(df[df['severity'] >= 7])
            
            # MITRE ATT&CK mapping
            mitre_mappings = {}
            if 'attack_type' in df.columns:
                mitre_mappings = self._map_to_mitre(df)
            
            return {
                "total_attacks": int(total_attacks),
                "unique_attackers": int(unique_ips),
                "attack_distribution": attack_dist,
                "hourly_pattern": hourly_attacks,
                "average_severity": round(float(avg_severity), 2),
                "high_severity_attacks": int(high_severity),
                "mitre_techniques": mitre_mappings,
                "timeline": self._create_timeline(df) if 'timestamp' in df.columns else []
            }
            
        except Exception as e:
            logger.error(f"Error in analysis: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "total_attacks": 0,
                "unique_attackers": 0,
                "attack_distribution": {},
                "hourly_pattern": {},
                "average_severity": 0,
                "high_severity_attacks": 0,
                "mitre_techniques": {},
                "timeline": []
            }
    
    def _map_to_mitre(self, df: pd.DataFrame) -> Dict[str, int]:
        """Map attacks to MITRE ATT&CK techniques"""
        mitre_mapping = {
            "brute_force": "T1110",
            "port_scan": "T1046",
            "malware": "T1204",
            "ddos": "T1498",
            "exploit": "T1210",
            "phishing": "T1566",
            "credential_theft": "T1078",
            "command_execution": "T1059",
            "connection_attempt": "T1078",
            "session_closed": "T1078",
            "malware_download": "T1105",
            "destructive_command": "T1485",
            "data_exfiltration": "T1041",
            "sql_injection": "T1190",
            "xss": "T1059.007",
            "other": "T1040"
        }
        
        technique_counts = {}
        if 'attack_type' in df.columns:
            for attack_type in df['attack_type'].unique():
                technique = mitre_mapping.get(str(attack_type), "T1040")
                count = len(df[df['attack_type'] == attack_type])
                technique_counts[technique] = technique_counts.get(technique, 0) + count
        
        return technique_counts
    
    # async def analyze(self) -> Dict[str, Any]:
    #     """Perform comprehensive threat analysis"""
        
    #     if not self.data:
    #         logger.warning("No data provided for analysis")
    #         return {}
        
    #     try:
    #         # Convert to DataFrame for analysis
    #         df = pd.DataFrame(self.data)
            
    #         # Basic statistics
    #         total_attacks = len(df)
    #         unique_ips = df['source_ip'].nunique() if 'source_ip' in df.columns else 0
            
    #         # Attack type distribution
    #         if 'attack_type' in df.columns:
    #             attack_dist = df['attack_type'].value_counts().to_dict()
    #         else:
    #             attack_dist = {}
            
    #         # Timeline analysis
    #         if 'timestamp' in df.columns and len(df) > 0:
    #             try:
    #                 df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
    #                 hourly_attacks = df.groupby('hour').size().to_dict()
    #             except Exception as e:
    #                 logger.warning(f"Error creating timeline: {e}")
    #                 hourly_attacks = {}
    #         else:
    #             hourly_attacks = {}
            
    #         # Severity analysis
    #         avg_severity = df['severity'].mean() if 'severity' in df.columns and len(df) > 0 else 0
    #         high_severity = len(df[df['severity'] >= 7]) if 'severity' in df.columns else 0
            
    #         # MITRE ATT&CK mapping
    #         mitre_mappings = await self._map_to_mitre(df) if 'attack_type' in df.columns else {}
            
    #         return {
    #             "total_attacks": int(total_attacks),
    #             "unique_attackers": int(unique_ips),
    #             "attack_distribution": attack_dist,
    #             "hourly_pattern": hourly_attacks,
    #             "average_severity": round(float(avg_severity), 2),
    #             "high_severity_attacks": int(high_severity),
    #             "mitre_techniques": mitre_mappings,
    #             "timeline": self._create_timeline(df) if 'timestamp' in df.columns else []
    #         }
            
    #     except Exception as e:
    #         logger.error(f"Error in analysis: {e}")
    #         # Return empty but valid structure
    #         return {
    #             "total_attacks": 0,
    #             "unique_attackers": 0,
    #             "attack_distribution": {},
    #             "hourly_pattern": {},
    #             "average_severity": 0,
    #             "high_severity_attacks": 0,
    #             "mitre_techniques": {},
    #             "timeline": []
    #         }
    
    def _analyze_geolocation(self, df: pd.DataFrame) -> List[Dict]:
        """Analyze geographical distribution of attacks"""
        countries = []
        
        for ip in df['source_ip'].unique():
            if ip != "unknown" and self.geoip_reader:
                try:
                    response = self.geoip_reader.city(ip)
                    countries.append({
                        "ip": ip,
                        "country": response.country.name,
                        "city": response.city.name,
                        "latitude": response.location.latitude,
                        "longitude": response.location.longitude
                    })
                except:
                    continue
        
        # Count occurrences
        country_counter = Counter([c['country'] for c in countries])
        return [
            {"country": country, "count": count}
            for country, count in country_counter.most_common()
        ]
    
    def _create_timeline(self, df: pd.DataFrame) -> List[Dict]:
        """Create timeline data for visualization"""
        df['date'] = df['timestamp'].dt.date
        timeline = df.groupby('date').size().reset_index(name='count')
        
        return [
            {"date": str(row['date']), "count": row['count']}
            for _, row in timeline.iterrows()
        ]
    
    async def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get real-time dashboard statistics"""
        if not self.data:
            return {}
        
        df = pd.DataFrame(self.data)
        last_24h = datetime.now() - timedelta(hours=24)
        recent_attacks = df[df['timestamp'] >= last_24h]
        
        return {
            "attacks_last_24h": len(recent_attacks),
            "top_attack_type": recent_attacks['attack_type'].mode().iloc[0] if not recent_attacks.empty else "None",
            "unique_attackers_24h": recent_attacks['source_ip'].nunique(),
            "current_threat_level": self._calculate_threat_level(recent_attacks)
        }
    
    def _calculate_threat_level(self, df: pd.DataFrame) -> str:
        """Calculate current threat level"""
        if df.empty:
            return "Low"
        
        high_sev = len(df[df['severity'] >= 8])
        total = len(df)
        
        ratio = high_sev / total if total > 0 else 0
        
        if ratio > 0.3:
            return "Critical"
        elif ratio > 0.15:
            return "High"
        elif ratio > 0.05:
            return "Medium"
        else:
            return "Low"