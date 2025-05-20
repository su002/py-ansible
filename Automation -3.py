#!/usr/bin/env python3
"""
安全增强版自动化运维脚本
新增功能：
1. 敏感配置加密存储
2. 强化SSL证书验证
3. 审计日志系统
4. 双因素认证机制
"""

import os
import shutil
import sys
import time
import psutil
import smtplib
import logging
import requests
import json
import base64
from datetime import datetime
from email.mime.text import MIMEText
from configparser import ConfigParser
from cryptography.fernet import Fernet
import pyotp
import hvac

# 安全相关配置
CONFIG_FILE = "server_monitor.secure.ini"
KEY_FILE = ".monitor.key"
AUDIT_LOG = "audit.log"

# 初始化加密模块
class CryptoManager:
    def __init__(self):
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)

    def _load_or_generate_key(self):
        """安全生成/获取加密密钥"""
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as f:
                f.write(key)
            os.chmod(KEY_FILE, 0o400)
            return key

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, data):
        return self.cipher.decrypt(data.encode()).decode()

class AuditLog:
    def __init__(self):
        self.logger = logging.getLogger('AUDIT')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(AUDIT_LOG)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
    
    def record(self, action, user, status, details=""):
        entry = f"USER={user} | ACTION={action} | STATUS={status} | DETAILS={details}"
        self.logger.info(entry)

class TwoFactorAuth:
    def __init__(self, config):
        self.config = config
        self.totp = pyotp.TOTP(config.get('Security', 'totp_secret', fallback=""))

    def verify_otp(self, code):
        return self.totp.verify(code)

    def generate_qrcode(self):
        return self.totp.provisioning_uri(
            name=self.config.get('Security', 'service_account'),
            issuer_name="ServerMonitor"
        )

class SecureServerMonitor(ServerMonitor):
    def __init__(self):
        self.crypto = CryptoManager()
        self.audit = AuditLog()
        self.tfa = None
        
        if not os.path.exists(CONFIG_FILE):
            self.create_secure_config()
            
        super().__init__()
        
        # 初始化双因素认证
        self.tfa = TwoFactorAuth(self.config)
        
        # 强化SSL验证
        requests.packages.urllib3.disable_warnings()
        self.session = requests.Session()
        self.session.verify = self.config.get('Security', 'ca_bundle', fallback=True)

    def create_secure_config(self):
        """创建加密配置文件"""
        config = ConfigParser()
        
        # 加密敏感字段
        crypto = CryptoManager()
        config['Security'] = {
            'ca_bundle': '/path/to/ca-bundle.crt',
            'totp_secret': crypto.encrypt(pyotp.random_base32()),
            'service_account': 'monitor_admin'
        }
        
        # 其他加密字段示例
        config['Email']['email_password'] = crypto.encrypt('your_password')
        config['SMS']['apikey'] = crypto.encrypt('sms_api_key')
        
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
        os.chmod(CONFIG_FILE, 0o600)

    def read_config(self):
        """读取并解密配置"""
        raw_config = ConfigParser()
        raw_config.read(CONFIG_FILE)
        
        # 解密敏感字段
        for section in ['Email', 'SMS', 'Voice', 'Security']:
            if raw_config.has_section(section):
                for key in raw_config[section]:
                    if key.endswith('_secret') or 'password' in key:
                        raw_config[section][key] = self.crypto.decrypt(
                            raw_config[section][key]
                        )
        return raw_config

    def secure_request(self, method, url, **kwargs):
        """安全网络请求方法"""
        try:
            response = self.session.request(method, url, **kwargs)
            self.audit.record(
                "NETWORK_REQUEST",
                "system",
                "SUCCESS",
                f"{method} {url} - {response.status_code}"
            )
            return response
        except requests.exceptions.SSLError as e:
            self.audit.record(
                "NETWORK_REQUEST",
                "system",
                "FAILURE",
                f"SSL验证失败: {str(e)}"
            )
            raise
        except Exception as e:
            self.audit.record(
                "NETWORK_REQUEST",
                "system",
                "FAILURE",
                str(e)
            )
            raise

    def send_wechat(self, message):
        """安全版企业微信通知"""
        webhook_url = self.config.get('WeChat', 'webhook_url')
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"**安全告警**\n>{message}"
            }
        }
        self.secure_request('POST', webhook_url, json=payload, timeout=5)

    def sensitive_operation(self, action):
        """执行敏感操作前的双因素认证"""
        user = os.getenv('USER')
        if self.config.getboolean('Security', 'require_2fa'):
            code = input("请输入双因素认证码: ")
            if not self.tfa.verify_otp(code):
                self.audit.record(
                    "AUTHENTICATION",
                    user,
                    "FAILURE",
                    action
                )
                raise PermissionError("双因素认证失败")
            
        self.audit.record(
            "SENSITIVE_OPERATION",
            user,
            "SUCCESS",
            action
        )

    def run(self):
        """安全增强主循环"""
        # 启动时审计
        self.audit.record("SYSTEM", "daemon", "STARTUP", "监控服务启动")
        
        try:
            while True:
                # 执行系统检查...
                # 执行日志轮转前验证
                if self.config.getboolean('Security', 'require_2fa'):
                    self.sensitive_operation("LOG_ROTATION")
                self.log_rotation()
                
                time.sleep(self.config.getint('Settings', 'check_interval'))
                
        except KeyboardInterrupt:
            self.audit.record("SYSTEM", "daemon", "SHUTDOWN", "正常停止")
        except Exception as e:
            self.audit.record("SYSTEM", "daemon", "CRASH", str(e))
            raise

# 配置文件示例新增内容
"""
[Security]
ca_bundle = /etc/ssl/certs/ca-certificates.crt
require_2fa = true
totp_secret = {加密后的密钥}
service_account = monitor_admin

[Vault]
enabled = false
address = https://vault.example.com
token = {加密后的token}
"""

if __name__ == "__main__":
    # 首次运行设置
    if not os.path.exists(CONFIG_FILE):
        SecureServerMonitor().create_secure_config()
        print("安全配置文件已生成，请完成以下操作：")
        print("1. 修改配置文件权限：chmod 600", CONFIG_FILE)
        print("2. 扫描二维码配置双因素认证：")
        monitor = SecureServerMonitor()
        print(monitor.tfa.generate_qrcode())
        sys.exit(0)
        
    monitor = SecureServerMonitor()
    monitor.run()