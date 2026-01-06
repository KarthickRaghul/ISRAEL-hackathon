import random
import ipaddress
import string
from dataset_loader import DatasetLoader
import string
from datetime import datetime, timedelta
from typing import List, Dict, Any

class AttackSimulator:
    """
    Generates specific attack traffic patterns based on configuration.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.iot_config = config["attacks"]["iot_bruteforce"]
        self.dns_config = config["attacks"]["dns_tunneling"]
        self.beacon_config = config["attacks"]["beaconing"]
        self.api_abuse_config = config["attacks"].get("api_abuse", {"enabled": False})
        self.clickjacking_config = config["attacks"].get("clickjacking", {"enabled": False})
        
        self.external_cidrs = [ipaddress.IPv4Network(cidr) for cidr in config["network"]["external_cidrs"]]
        self.internal_cidrs = [ipaddress.IPv4Network(cidr) for cidr in config["network"]["internal_cidrs"]]
        
        # Dataset Integration
        self.use_dataset = config.get("dataset", {}).get("enabled", False)
        if self.use_dataset:
            self.loader = DatasetLoader(config["dataset"]["path"])

    def _get_random_external_ip(self) -> str:
        subnet = random.choice(self.external_cidrs)
        # Generate a random host within the subnet
        # random.choice is slow for large networks, simpler to verify logic
        # For /24 or /16, we can pick a random offset
        network_int = int(subnet.network_address)
        max_hosts = subnet.num_addresses - 1
        return str(ipaddress.IPv4Address(network_int + random.randint(1, max_hosts)))

    def _get_start_time(self, base_time: datetime, duration_hours: int) -> datetime:
        """Returns a random timestamp within the simulation window."""
        offset_seconds = random.randint(0, duration_hours * 3600)
        return base_time + timedelta(seconds=offset_seconds)

    def generate_iot_bruteforce(self, start_time: datetime, duration_hours: int, src_ip_override: str = None) -> List[Dict[str, Any]]:
        if not self.iot_config["enabled"]:
            return []
            
        logs = []
        target_port = self.iot_config["target_port"]
        attempts = self.iot_config["attempts_per_run"]
        
        
        iot_count = self.config["devices"]["iot"]["count"]
        victim_idx = random.randint(1, iot_count)
        
        if self.use_dataset:
            devices = self.loader.get_devices()
            if devices:
                src_ip = random.choice(devices)
                dev_name = f"iot-{src_ip.split('.')[-1]}"
            else:
                 src_ip = f"192.168.1.{200 + victim_idx}"
                 dev_name = f"iot-device-{victim_idx}"
        else:
            src_ip = f"192.168.1.{200 + victim_idx}"
            dev_name = f"{self.config['devices']['iot']['prefix']}{victim_idx}"
        
        dst_ip = self._get_random_external_ip()
        
       
        attack_start = self._get_start_time(start_time, duration_hours)
        
        for i in range(attempts):
            timestamp = attack_start + timedelta(milliseconds=i * random.randint(50, 200)) # Fast interval
            
   
            is_success = random.random() < self.iot_config["success_rate"]
            action = "accept" if is_success else "deny"
            
            
            log = {
                "timestamp": timestamp,
                "srcip": src_ip,
                "dstip": dst_ip,
                "srcport": random.randint(10000, 65000),
                "dstport": target_port,
                "proto": 6,
                "service": "SSH",
                "action": "accept", 
                "policyid": 101,
                "sentbyte": random.randint(100, 300), 
                "rcvdbyte": random.randint(100, 300),
                "duration": random.randint(1, 3),
                "user": "N/A",
                "device_type": "iot_camera",
                "level": "notice",
                "logid": "0000000013",
                "msg": "SSH connection established",
                "alert_name": "SSH Brute Force"
            }
            logs.append(log)
            
        return logs

    def generate_dns_tunneling(self, start_time: datetime, duration_hours: int, src_ip_override: str = None) -> List[Dict[str, Any]]:
        if not self.dns_config["enabled"]:
            return []
            
        logs = []
        domain_suffix = self.dns_config["domain_suffix"]
        
    
        src_ip = "192.168.1.105"
        if src_ip_override:
            src_ip = src_ip_override
        elif self.use_dataset:
            devices = self.loader.get_devices()
            if devices:
                src_ip = random.choice(devices) 
        dns_server = self.config["network"]["dns_servers"][0] # 8.8.8.8
        
   
        total_minutes = duration_hours * 60
        rate = self.dns_config["query_rate_per_minute"]
        total_queries = total_minutes * rate
        
        current_time = start_time
        
        for i in range(total_queries):
            current_time += timedelta(seconds=60/rate + random.uniform(-0.1, 0.1))
            
            subdomain_len = random.randint(30, 60) # Long subdomain
            subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=subdomain_len))
            fqdn = f"{subdomain}.{domain_suffix}"
            
            log = {
                "timestamp": current_time,
                "srcip": src_ip,
                "dstip": dns_server,
                "srcport": random.randint(10000, 65000),
                "dstport": 53,
                "proto": 17,
                "service": "DNS",
                "action": "accept",
                "policyid": 1,
                "sentbyte": random.randint(80, 150),
                "rcvdbyte": random.randint(200, 500),
                "duration": 0,
                "user": "bob.smith",
                "device_type": "Windows PC",
                "level": "notice",
                "logid": "0000000013",
                "qname": fqdn,
                "alert_name": "DNS Tunneling"
            }
            logs.append(log)
            
        return logs

    def generate_beaconing(self, start_time: datetime, duration_hours: int, src_ip_override: str = None) -> List[Dict[str, Any]]:
        if not self.beacon_config["enabled"]:
            return []
            
        logs = []
        c2_ip = self.beacon_config["target_ip"]
        interval = self.beacon_config["interval_seconds"]
        jitter = self.beacon_config["jitter_percent"]
        
        src_ip = "192.168.1.55"
        if src_ip_override:
            src_ip = src_ip_override
        elif self.use_dataset:
             devices = self.loader.get_devices()
             if devices:
                 src_ip = random.choice(devices)
        
        current_time = start_time
        end_time = start_time + timedelta(hours=duration_hours)
        
        while current_time < end_time:
            jitter_sec = interval * jitter
            actual_interval = interval + random.uniform(-jitter_sec, jitter_sec)
            current_time += timedelta(seconds=actual_interval)
            
            if current_time > end_time:
                break
                
            log = {
                "timestamp": current_time,
                "srcip": src_ip,
                "dstip": c2_ip,
                "srcport": random.randint(49152, 65535), 
                "dstport": 443,
                "proto": 6,
                "service": "HTTPS",
                "action": "accept",
                "policyid": 1,
                "sentbyte": 1200,
                "rcvdbyte": 4500,
                "duration": random.randint(1, 2),
                "user": "SYSTEM",
                "device_type": "srv-db-01",
                "level": "notice",
                "logid": "0000000013",
                "alert_name": "C2 Beaconing"
            }
            logs.append(log)
            
        return logs

    def generate_api_abuse(self, start_time: datetime, duration_hours: int, src_ip_override: str = None) -> List[Dict[str, Any]]:
        if not self.api_abuse_config.get("enabled", False):
            return []
            
        logs = []
        endpoints = self.api_abuse_config.get("target_endpoints", ["/api/v1/data"])
        rate = self.api_abuse_config.get("requests_per_minute", 20)
        
        # Attacker is external or compromised internal? Usually external for public API or compromised credential
        src_ip = "203.0.113.45" 
        if src_ip_override:
            src_ip = src_ip_override
            
        target_ip = "192.168.1.10" # Internal API Gateway
        
        total_requests = int(duration_hours * 60 * rate)
        current_time = start_time
        
        for _ in range(total_requests):
            current_time += timedelta(seconds=60/rate + random.uniform(-0.5, 0.5))
            
            endpoint = random.choice(endpoints)
            status = random.choices([200, 401, 403, 429], weights=[10, 40, 40, 10], k=1)[0]
            
            log = {
                "timestamp": current_time,
                "srcip": src_ip,
                "dstip": target_ip,
                "srcport": random.randint(10000, 65000), 
                "dstport": 443,
                "proto": 6,
                "service": "HTTPS",
                "action": "deny" if status in [401, 403] else "accept",
                "policyid": 2,
                "sentbyte": random.randint(200, 500),
                "rcvdbyte": random.randint(100, 300),
                "duration": random.randint(0, 1),
                "user": "unknown",
                "device_type": "firewall",
                "level": "warning",
                "logid": "0000000014",
                "url": endpoint,
                "status_code": status,
                "http_method": "GET",
                "msg": f"API Abuse Detection: Excessive requests to {endpoint}",
                "alert_name": "API Abuse"
            }
            logs.append(log)
            
        return logs

    def generate_clickjacking(self, start_time: datetime, duration_hours: int, src_ip_override: str = None) -> List[Dict[str, Any]]:
        if not self.clickjacking_config.get("enabled", False):
            return []
            
        logs = []
        target_url = self.clickjacking_config.get("target_url", "http://example.com")
        referers = self.clickjacking_config.get("suspicious_referers", ["http://bad-site.com"])
        
        # Victim internal IP accessing compromised site OR External attacker loading iframe?
        # Usually internal user visiting bad site which loads internal site in iframe.
        # So SrcIP = Internal User, DstIP = Internal Site (via bad referrer) or External Site?
        # Let's say WAF sees request to Target URL with Bad Referer.
        
        if self.use_dataset:
             devices = self.loader.get_devices()
             src_ip = random.choice(devices) if devices else "192.168.1.50"
        else:
             src_ip = "192.168.1.50" # Victim User
             
        if src_ip_override:
            src_ip = src_ip_override
            
        dst_ip = "192.168.1.200" # Internal Web Server
        
        # A few events
        count = random.randint(1, 5)
        current_time = start_time
        
        for _ in range(count):
            current_time += timedelta(minutes=random.randint(1, 60))
            ref = random.choice(referers)
            
            log = {
                "timestamp": current_time,
                "srcip": src_ip,
                "dstip": dst_ip,
                "srcport": random.randint(10000, 65000), 
                "dstport": 80,
                "proto": 6,
                "service": "HTTP",
                "action": "deny", # Blocked by WAF/X-Frame-Options
                "policyid": 3,
                "sentbyte": random.randint(300, 600),
                "rcvdbyte": 0,
                "duration": 0,
                "user": "user-victim",
                "device_type": "workstation",
                "level": "alert",
                "logid": "0000000015",
                "url": target_url,
                "status_code": 403,
                "http_method": "GET",
                "msg": f"Clickjacking Attempt Blocked: Referer {ref} not allowed",
                "alert_name": "Clickjacking"
            }
            logs.append(log)
            
        return logs
