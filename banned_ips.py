import os
import json
import datetime
import logging

# Path to the banned IPs file
BANNED_IPS_FILE = "banned_ips.json"

# Logger
logger = logging.getLogger(__name__)

def init_banned_ips():
    """Initialize the banned IPs file if it doesn't exist."""
    if not os.path.exists(BANNED_IPS_FILE):
        banned_data = {
            "banned_ips": []
        }
        with open(BANNED_IPS_FILE, 'w') as f:
            json.dump(banned_data, f, indent=2)
        logger.info(f"Banned IPs file {BANNED_IPS_FILE} created")

def get_banned_ips():
    """Get the list of banned IPs."""
    try:
        with open(BANNED_IPS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading banned IPs: {str(e)}", exc_info=True)
        return {"banned_ips": []}

def is_ip_banned(ip_address):
    """Check if an IP address is banned."""
    banned_data = get_banned_ips()
    for ban in banned_data["banned_ips"]:
        if ban["ip"] == ip_address:
            # Check if ban has expired
            if "expires_at" in ban and ban["expires_at"]:
                expires_at = datetime.datetime.fromisoformat(ban["expires_at"])
                if datetime.datetime.now() > expires_at:
                    # Ban has expired
                    continue
            return ban
    return None

def ban_ip(ip_address, reason="No reason provided", duration_days=None):
    """Ban an IP address."""
    try:
        banned_data = get_banned_ips()
        
        # Check if IP is already banned
        for ban in banned_data["banned_ips"]:
            if ban["ip"] == ip_address:
                ban["reason"] = reason
                ban["banned_at"] = datetime.datetime.now().isoformat()
                if duration_days:
                    ban["expires_at"] = (datetime.datetime.now() + datetime.timedelta(days=duration_days)).isoformat()
                else:
                    ban["expires_at"] = None
                break
        else:
            # Add new ban
            new_ban = {
                "ip": ip_address,
                "reason": reason,
                "banned_at": datetime.datetime.now().isoformat()
            }
            if duration_days:
                new_ban["expires_at"] = (datetime.datetime.now() + datetime.timedelta(days=duration_days)).isoformat()
            else:
                new_ban["expires_at"] = None
            
            banned_data["banned_ips"].append(new_ban)
        
        with open(BANNED_IPS_FILE, 'w') as f:
            json.dump(banned_data, f, indent=2)
        
        logger.info(f"IP {ip_address} has been banned: {reason}")
        return True
    except Exception as e:
        logger.error(f"Error banning IP {ip_address}: {str(e)}", exc_info=True)
        return False

def unban_ip(ip_address):
    """Unban an IP address."""
    try:
        banned_data = get_banned_ips()
        
        for i, ban in enumerate(banned_data["banned_ips"]):
            if ban["ip"] == ip_address:
                del banned_data["banned_ips"][i]
                
                with open(BANNED_IPS_FILE, 'w') as f:
                    json.dump(banned_data, f, indent=2)
                
                logger.info(f"IP {ip_address} has been unbanned")
                return True
        
        logger.warning(f"IP {ip_address} was not found in the ban list")
        return False
    except Exception as e:
        logger.error(f"Error unbanning IP {ip_address}: {str(e)}", exc_info=True)
        return False

