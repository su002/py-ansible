#!/usr/bin/env python3
"""
增强版自动化运维脚本
新增功能：
1. 企业微信机器人集成
2. 钉钉机器人集成
3. 短信通知接口
4. 电话告警系统
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
from datetime import datetime
from email.mime.text import MIMEText
from configparser import ConfigParser

CONFIG_FILE = "server_monitor.ini"

logging.basicConfig(
    filename="monitor.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class NotificationManager:
    """统一通知管理类"""
    def __init__(self, config):
        self.config = config
        self.alert_modes = self._get_active_alert_modes()

    def _get_active_alert_modes(self):
        """获取启用的告警方式"""
        modes = []
        if self.config.getboolean('AlertSettings', 'enable_email', fallback=False):
            modes.append('email')
        if self.config.getboolean('AlertSettings', 'enable_wechat', fallback=False):
            modes.append('wechat')
        if self.config.getboolean('AlertSettings', 'enable_dingtalk', fallback=False):
            modes.append('dingtalk')
        if self.config.getboolean('AlertSettings', 'enable_sms', fallback=False):
            modes.append('sms')
        if self.config.getboolean('AlertSettings', 'enable_voice', fallback=False):
            modes.append('voice')
        return modes

    def send_all(self, subject, message):
        """发送所有启用的通知方式"""
        for mode in self.alert_modes:
            try:
                if mode == 'email':
                    self.send_email(subject, message)
                elif mode == 'wechat':
                    self.send_wechat(message)
                elif mode == 'dingtalk':
                    self.send_dingtalk(message)
                elif mode == 'sms':
                    self.send_sms(message)
                elif mode == 'voice':
                    self.send_voice_call(subject)
            except Exception as e:
                logging.error(f"{mode}通知发送失败: {str(e)}")

    def send_email(self, subject, message):
        """发送邮件通知"""
        msg = MIMEText(message)
        msg['Subject'] = f"[SERVER ALERT] {subject}"
        msg['From'] = self.config.get('Email', 'email_from')
        msg['To'] = self.config.get('Email', 'email_to')
        
        with smtplib.SMTP(
            self.config.get('Email', 'smtp_server'),
            self.config.getint('Email', 'smtp_port')
        ) as server:
            server.starttls()
            server.login(
                self.config.get('Email', 'email_user'),
                self.config.get('Email', 'email_password')
            )
            server.send_message(msg)

    def send_wechat(self, message):
        """发送企业微信机器人通知"""
        webhook_url = self.config.get('WeChat', 'webhook_url')
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"**服务器告警**\n>{message}\n>**发生时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }
        requests.post(webhook_url, json=payload, timeout=5)

    def send_dingtalk(self, message):
        """发送钉钉机器人通知"""
        webhook_url = self.config.get('DingTalk', 'webhook_url')
        secret = self.config.get('DingTalk', 'secret', fallback=None)
        
        timestamp = str(round(time.time() * 1000))
        sign = ""
        if secret:
            sign = self._generate_dingtalk_sign(timestamp, secret)
        
        payload = {
            "msgtype": "text",
            "text": {
                "content": f"服务器告警通知\n{message}\n时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }
        params = {"timestamp": timestamp}
        if sign:
            params["sign"] = sign
        requests.post(webhook_url, params=params, json=payload, timeout=5)

    def _generate_dingtalk_sign(self, timestamp, secret):
        """生成钉钉签名"""
        import hmac
        import hashlib
        message = f"{timestamp}\n{secret}"
        hmac_code = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        return hmac_code.base64().decode()

    def send_sms(self, message):
        """发送短信通知"""
        api_url = self.config.get('SMS', 'api_url')
        params = {
            "apikey": self.config.get('SMS', 'apikey'),
            "mobile": self.config.get('SMS', 'mobile'),
            "content": f"[运维告警]{message}"
        }
        requests.get(api_url, params=params, timeout=5)

    def send_voice_call(self, message):
        """发起语音电话告警"""
        api_url = self.config.get('Voice', 'api_url')
        payload = {
            "access_key": self.config.get('Voice', 'access_key'),
            "secret_key": self.config.get('Voice', 'secret_key'),
            "phone": self.config.get('Voice', 'alert_phone'),
            "content": message
        }
        requests.post(api_url, json=payload, timeout=5)

class ServerMonitor:
    def __init__(self):
        self.config = ConfigParser()
        if not os.path.exists(CONFIG_FILE):
            self.create_default_config()
        self.config.read(CONFIG_FILE)
        
        self.alert_cache = {'cpu': False, 'mem': False, 'disk': False}
        self.notifier = NotificationManager(self.config)

    def create_default_config(self):
        """新增配置项"""
        self.config['Thresholds'] = {
            # ...原有配置保持不变...
        }
        self.config['Settings'] = {
            # ...原有配置保持不变...
        }
        self.config['AlertSettings'] = {
            'enable_email': 'true',
            'enable_wechat': 'false',
            'enable_dingtalk': 'false',
            'enable_sms': 'false',
            'enable_voice': 'false'
        }
        self.config['WeChat'] = {
            'webhook_url': 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=YOUR_KEY'
        }
        self.config['DingTalk'] = {
            'webhook_url': 'https://oapi.dingtalk.com/robot/send?access_token=YOUR_TOKEN',
            'secret': ''
        }
        self.config['SMS'] = {
            'api_url': 'https://sms-api.example.com/send',
            'apikey': 'YOUR_API_KEY',
            'mobile': '13800138000'
        }
        self.config['Voice'] = {
            'api_url': 'https://voice-api.example.com/alert',
            'access_key': 'YOUR_AK',
            'secret_key': 'YOUR_SK',
            'alert_phone': '13800138000'
        }
        # ...保存配置...

    # ...原有方法保持不变...

    def evaluate_thresholds(self, metrics):
        alerts = []
        # ...原有阈值检查逻辑...
        if alerts:
            self.notifier.send_all("系统异常", "\n".join(alerts))
        return alerts

    # ...其他方法保持不变...

if __name__ == "__main__":
    monitor = ServerMonitor()
    logging.info("启动增强版监控服务")
    monitor.run()