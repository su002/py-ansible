#!/usr/bin/env python3
# """
# 服务器自动化运维脚本
# 功能：
# 1. 系统资源监控与告警
# 2. 日志文件自动轮转
# 3. 异常状态通知
# 4. 自定义阈值配置
# """

import os
import shutil
import sys
import time
import psutil
import smtplib
import logging
from datetime import datetime
from email.mime.text import MIMEText
from configparser import ConfigParser

# 配置文件路径
CONFIG_FILE = "server_monitor.ini"

# 初始化日志
logging.basicConfig(
    filename="monitor.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class ServerMonitor:
    def __init__(self):
        self.config = ConfigParser()
        if not os.path.exists(CONFIG_FILE):
            self.create_default_config()
        self.config.read(CONFIG_FILE)
        
        # 告警状态缓存
        self.alert_cache = {
            'cpu': False,
            'mem': False,
            'disk': False
        }

    def create_default_config(self):
        # """创建默认配置文件"""
        self.config['Thresholds'] = {
            'cpu_warning': '70',
            'cpu_critical': '90',
            'mem_warning': '75',
            'mem_critical': '85',
            'disk_warning': '80',
            'disk_critical': '90'
        }
        self.config['Settings'] = {
            'check_interval': '300',
            'log_dir': '/var/log/app',
            'max_log_size': '10485760',  
            'keep_logs': '7'
        }
        self.config['Email'] = {
            'smtp_server': 'smtp.example.com',
            'smtp_port': '587',
            'email_from': 'monitor@example.com',
            'email_to': 'admin@example.com',
            'email_user': 'user',
            'email_password': 'password'
        }
        with open(CONFIG_FILE, 'w') as f:
            self.config.write(f)

    def check_system_resources(self):
        # """检查系统资源使用情况"""
        try:
            # CPU使用率
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # 内存使用
            mem = psutil.virtual_memory()
            
            # 磁盘使用（监控根分区）
            disk = psutil.disk_usage('/')
            
            return {
                'cpu': cpu_percent,
                'mem': mem.percent,
                'disk': disk.percent
            }
        except Exception as e:
            logging.error(f"资源检查失败: {str(e)}")
            return None

    def log_rotation(self):
        # """日志文件轮转"""
        log_dir = self.config.get('Settings', 'log_dir')
        max_size = self.config.getint('Settings', 'max_log_size')
        keep_days = self.config.getint('Settings', 'keep_logs')
        
        try:
            for fname in os.listdir(log_dir):
                if fname.endswith('.log'):
                    file_path = os.path.join(log_dir, fname)
                    
                    # 检查文件大小
                    if os.path.getsize(file_path) > max_size:
                        self._compress_log(file_path)
                        
                    # 删除过期日志
                    if os.path.getmtime(file_path) < (time.time() - keep_days * 86400):
                        os.remove(file_path)
                        logging.info(f"删除过期日志: {fname}")
                        
        except Exception as e:
            logging.error(f"日志轮转失败: {str(e)}")

    def _compress_log(self, file_path):
        # """压缩日志文件"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        compressed_name = f"{os.path.basename(file_path)}_{timestamp}.gz"
        compressed_path = os.path.join(os.path.dirname(file_path), compressed_name)
        
        try:
            with open(file_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(file_path)
            logging.info(f"日志已压缩: {compressed_name}")
        except Exception as e:
            logging.error(f"日志压缩失败: {str(e)}")

    def send_alert(self, subject, message):
        # """发送告警邮件"""
        try:
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
            logging.info("告警邮件已发送")
        except Exception as e:
            logging.error(f"邮件发送失败: {str(e)}")

    def evaluate_thresholds(self, metrics):
        # """评估监控指标"""
        alerts = []
        
        # CPU检查
        if metrics['cpu'] > self.config.getfloat('Thresholds', 'cpu_critical'):
            if not self.alert_cache['cpu']:
                alerts.append(f"CPU CRITICAL: {metrics['cpu']}%")
                self.alert_cache['cpu'] = True
        elif metrics['cpu'] > self.config.getfloat('Thresholds', 'cpu_warning'):
            if not self.alert_cache['cpu']:
                alerts.append(f"CPU WARNING: {metrics['cpu']}%")
                self.alert_cache['cpu'] = True
        else:
            self.alert_cache['cpu'] = False
            
        # 内存检查（类似逻辑）
        # 磁盘检查（类似逻辑）
        
        return alerts

    def run(self):
        # """主循环"""
        while True:
            try:
                # 执行系统检查
                metrics = self.check_system_resources()
                if metrics:
                    alerts = self.evaluate_thresholds(metrics)
                    if alerts:
                        self.send_alert("系统异常", "\n".join(alerts))
                
                # 执行日志轮转
                self.log_rotation()
                
                # 休眠间隔
                time.sleep(self.config.getint('Settings', 'check_interval'))
                
            except KeyboardInterrupt:
                logging.info("监控服务已停止")
                sys.exit(0)
            except Exception as e:
                logging.error(f"主循环异常: {str(e)}")
                time.sleep(60)  # 异常后等待1分钟再重试

if __name__ == "__main__":
    monitor = ServerMonitor()
    logging.info("启动服务器监控服务")
    monitor.run()