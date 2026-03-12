#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F5 UCS 配置分析工具
分析 UCS 文件，生成 VS 配置表和未使用对象报告
"""

import tarfile
import zipfile
import json
import re
import os
import sys
import argparse
from pathlib import Path
from collections import defaultdict
import pandas as pd


class F5UCSAnalyzer:
    """F5 UCS 配置分析器"""
    
    # F5 系统默认对象（自动排除）
    SYSTEM_DEFAULTS = {
        'profiles': [
            'fastL4', 'tcp', 'udp', 'http', 'https', 'clientssl', 'serverssl',
            'fasthttp', 'oneconnect', 'stream', 'statistics', 'analytics',
            'request-adapt', 'response-adapt', 'rewrite', 'persist',
            'source_addr', 'cookie', 'dest_addr', 'hash', 'msrdp', 'sip_info',
            'ssl', 'sctp', 'diameter', 'dns', 'fix', 'ftp', 'gtp', 'icap',
            'iiop', 'ipother', 'mblb', 'mssql', 'mysql', 'oracle', 'pptp',
            'qoe', 'radius', 'ramcache', 'rtsp', 'sctp', 'sipsession',
            'spdy', 'tcp-analytics', 'tcp-lan-optimized', 'tcp-wan-optimized',
            'udp_gtm_dns', 'webacceleration', 'websocket', 'xml'
        ],
        'monitors': [
            'gateway_icmp', 'icmp', 'tcp', 'tcp_half_open', 'udp', 'http',
            'https', 'ftp', 'pop3', 'smtp', 'snmp_dca', 'snmp_dca_base',
            'real_server', 'rpc', 'sip', 'radius', 'diameter', 'dns',
            'firepass', 'gwm', 'imap', 'ldap', 'mssql', 'mysql', 'nntp',
            'oracle', 'postgresql', 'radius_accounting', 'scripted', 'smb',
            'soap', 'wmi', 'tcp_echo', 'tcp', 'udp'
        ],
        'irules': [
            '_sys_auth_ssl_cc_ldap', '_sys_auth_ssl_crldp', '_sys_auth_ssl_ocsp',
            '_sys_auth_ssl_ldap', '_sys_https_redirect', '_sys_APM_Websocket',
            '_sys_APM_activesync', '_sys_APM_ExchangeSupport_helper',
            '_sys_APM_ExchangeSupport_main', '_sys_APM_owa', '_sys_APM_sharepoint',
            '_sys_APM_tmpl_info', '_sys_APM_activesync_v2'
        ],
        'pools': [],
        'nodes': [],
        'snats': ['snatpool', 'automap', 'none'],
        'policies': [],
        'datagroups': ['__dg_internal']
    }
    
    def __init__(self, ucs_path, output_dir):
        self.ucs_path = Path(ucs_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 存储解析的配置
        self.config = {
            'virtuals': {},
            'pools': {},
            'profiles': {},
            'irules': {},
            'monitors': {},
            'nodes': {},
            'snats': {},
            'policies': {},
            'datagroups': {},
            'ssl_profiles': {'clientssl': {}, 'serverssl': {}},
            'persistence': {}
        }
        
        # 引用关系
        self.references = defaultdict(set)
        
    def extract_ucs(self):
        """解压 UCS 文件"""
        extract_dir = self.output_dir / 'extracted'
        extract_dir.mkdir(exist_ok=True)
        
        print(f"正在解压 UCS 文件: {self.ucs_path}")
        
        # 安全的解压函数，处理 Windows 不支持的文件名
        def safe_extract(tar_or_zip, extract_path):
            if isinstance(tar_or_zip, tarfile.TarFile):
                for member in tar_or_zip.getmembers():
                    # 清理文件名中的非法字符
                    safe_name = self._sanitize_filename(member.name)
                    if safe_name:
                        member.name = safe_name
                        try:
                            tar_or_zip.extract(member, extract_path)
                        except Exception as e:
                            print(f"警告: 无法解压文件 {member.name}: {e}")
            else:  # ZipFile
                for member in tar_or_zip.namelist():
                    safe_name = self._sanitize_filename(member)
                    if safe_name:
                        try:
                            content = tar_or_zip.read(member)
                            target_path = extract_path / safe_name
                            target_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(target_path, 'wb') as f:
                                f.write(content)
                        except Exception as e:
                            print(f"警告: 无法解压文件 {member}: {e}")
        
        if tarfile.is_tarfile(self.ucs_path):
            with tarfile.open(self.ucs_path, 'r:gz') as tar:
                safe_extract(tar, extract_dir)
        elif zipfile.is_zipfile(self.ucs_path):
            with zipfile.ZipFile(self.ucs_path, 'r') as zf:
                safe_extract(zf, extract_dir)
        else:
            raise ValueError("不支持的文件格式，需要 .ucs 或 .tar.gz 文件")
        
        # 查找 bigip.conf 文件
        config_files = list(extract_dir.rglob('bigip.conf'))
        if not config_files:
            raise FileNotFoundError("在 UCS 文件中未找到 bigip.conf")
        
        return config_files[0]
    
    def _sanitize_filename(self, filename):
        """清理文件名中的非法字符"""
        if not filename:
            return None
        
        # Windows 非法字符: < > : " | ? *
        import re
        # 替换非法字符为下划线
        safe_name = re.sub(r'[<>:"|?*]', '_', filename)
        
        # 移除控制字符
        safe_name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', safe_name)
        
        # 确保不以空格或点结尾
        safe_name = safe_name.rstrip('. ')
        
        # 跳过危险路径
        if '..' in safe_name or safe_name.startswith('/'):
            return None
        
        return safe_name
    
    def parse_config(self, config_file):
        """解析 bigip.conf 配置文件"""
        print(f"正在解析配置文件: {config_file}")
        
        with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # 解析 Virtual Server
        self._parse_virtuals(content)
        
        # 解析 Pool
        self._parse_pools(content)
        
        # 解析 Profile
        self._parse_profiles(content)
        
        # 解析 iRule
        self._parse_irules(content)
        
        # 解析 Monitor
        self._parse_monitors(content)
        
        # 解析 Node
        self._parse_nodes(content)
        
        # 解析 SNAT
        self._parse_snats(content)
        
        # 解析 Policy
        self._parse_policies(content)
        
        # 解析 Data Group
        self._parse_datagroups(content)
        
        print("配置解析完成")
    
    def _parse_virtuals(self, content):
        """解析 Virtual Server 配置"""
        # 使用更健壮的方式解析嵌套大括号
        pattern = r'ltm virtual\s+(\S+)\s*\{'
        matches = list(re.finditer(pattern, content))
        
        for i, match in enumerate(matches):
            name = match.group(1)
            start_pos = match.end() - 1  # 包含开头的 {
            
            # 找到匹配的结束大括号
            brace_count = 0
            end_pos = start_pos
            for j, char in enumerate(content[start_pos:]):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = start_pos + j + 1
                        break
            
            config = content[start_pos:end_pos]
            
            vs_info = {
                'name': name,
                'destination': self._extract_value(config, 'destination'),
                'ip_protocol': self._extract_value(config, 'ip-protocol'),
                'pool': self._extract_pool(config),
                'profiles': self._extract_profiles(config),
                'rules': self._extract_rules(config),
                'policies': self._extract_policies(config),
                'snat': self._extract_snat(config),
                'persist': self._extract_persistence(config),
                'vlans': self._extract_list(config, 'vlans'),
                'disabled': 'disabled' in config
            }
            self.config['virtuals'][name] = vs_info
            
            # 记录引用关系
            if vs_info['pool']:
                self.references[name].add(('pool', vs_info['pool']))
            for profile in vs_info['profiles']:
                self.references[name].add(('profile', profile))
            for rule in vs_info['rules']:
                self.references[name].add(('irule', rule))
    
    def _extract_pool(self, config):
        """提取 pool 配置，处理各种格式"""
        # 匹配 pool 行，支持 /Common/pool_name 格式
        pattern = r'^\s*pool\s+([\w/\-_]+)'
        match = re.search(pattern, config, re.MULTILINE)
        if match:
            pool_name = match.group(1).strip()
            # 标准化 pool 名称
            if not pool_name.startswith('/'):
                pool_name = f'/Common/{pool_name}'
            return pool_name
        return ''
    
    def _extract_profiles(self, config):
        """提取 profiles 配置"""
        profiles = []
        # 匹配 profiles 块
        pattern = r'profiles\s*\{([^}]+)\}'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            content = match.group(1)
            # 提取每个 profile 名称
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    # 匹配 profile 名称（可能包含 /Common/）
                    profile_match = re.match(r'([\w/\-_.]+)', line)
                    if profile_match:
                        profile = profile_match.group(1)
                        if profile and profile not in ['{', '}']:
                            profiles.append(profile)
        return profiles
    
    def _extract_rules(self, config):
        """提取 rules (iRules) 配置"""
        rules = []
        # 匹配 rules 块
        pattern = r'rules\s*\{([^}]+)\}'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            content = match.group(1)
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and line not in ['{', '}']:
                    rules.append(line)
        return rules
    
    def _extract_policies(self, config):
        """提取 policies 配置"""
        policies = []
        pattern = r'policies\s*\{([^}]+)\}'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            content = match.group(1)
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and line not in ['{', '}']:
                    policies.append(line)
        return policies
    
    def _extract_snat(self, config):
        """提取 SNAT 配置"""
        pattern = r'source-address-translation\s*\{[^}]*type\s+(\S+)'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            return match.group(1)
        # 也检查简单的 snat 配置
        pattern = r'snat\s+(\S+)'
        match = re.search(pattern, config)
        if match:
            return match.group(1)
        return ''
    
    def _extract_persistence(self, config):
        """提取 Persistence 配置，返回结构化数据"""
        persistence_list = []
        
        # 方法1: 使用大括号计数法匹配 persist 块
        # 格式:
        # persist {
        #     /Common/source_addr {
        #         default yes
        #     }
        # }
        persist_start = config.find('persist {')
        if persist_start != -1:
            start_pos = persist_start + len('persist {') - 1
            
            # 找到 persist 块的结束位置
            brace_count = 0
            end_pos = start_pos
            for j, char in enumerate(config[start_pos:]):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = start_pos + j + 1
                        break
            
            persist_content = config[start_pos:end_pos]
            
            # 提取每个 persistence profile
            # 格式: /Common/source_addr { default yes }
            # 使用大括号计数法提取每个 profile
            profile_pattern = r'([\w/\-_.]+)\s*\{'
            for match in re.finditer(profile_pattern, persist_content):
                profile_name = match.group(1)
                profile_start = match.end() - 1
                
                # 找到 profile 配置的结束位置
                brace_count = 0
                profile_end = profile_start
                for j, char in enumerate(persist_content[profile_start:]):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            profile_end = profile_start + j + 1
                            break
                
                profile_config = persist_content[profile_start:profile_end]
                
                persist_info = {
                    'profile': profile_name,
                    'profile_short': profile_name.split('/')[-1] if '/' in profile_name else profile_name,
                    'partition': self._get_partition(profile_name),
                    'default': 'yes' if 'default yes' in profile_config else 'no',
                    'type': self._get_persistence_type(profile_name)
                }
                persistence_list.append(persist_info)
        
        # 方法2: 匹配简单的 persist 行（单行格式）
        # 格式: persist /Common/source_addr
        if not persistence_list:
            pattern = r'^\s*persist\s+([\w/\-_.]+)'
            match = re.search(pattern, config, re.MULTILINE)
            if match:
                profile_name = match.group(1).strip()
                persist_info = {
                    'profile': profile_name,
                    'profile_short': profile_name.split('/')[-1] if '/' in profile_name else profile_name,
                    'partition': self._get_partition(profile_name),
                    'default': 'yes',  # 简单格式默认就是 default
                    'type': self._get_persistence_type(profile_name)
                }
                persistence_list.append(persist_info)
        
        return persistence_list
    
    def _get_partition(self, name):
        """从完整路径中提取分区名"""
        if name.startswith('/'):
            parts = name.split('/')
            if len(parts) >= 2:
                return parts[1]
        return 'Common'
    
    def _get_persistence_type(self, profile_name):
        """获取 persistence 类型说明"""
        type_map = {
            'source_addr': '源地址持久性 (Source IP)',
            'dest_addr': '目的地址持久性 (Destination IP)',
            'cookie': 'Cookie 持久性',
            'ssl': 'SSL 会话 ID 持久性',
            'hash': '哈希持久性',
            'msrdp': 'RDP 持久性',
            'sip_info': 'SIP 持久性',
            'universal': '通用持久性',
            'dest_addr': '目的地址持久性'
        }
        
        short_name = profile_name.split('/')[-1] if '/' in profile_name else profile_name
        return type_map.get(short_name, f'自定义持久性 ({short_name})')
    
    def _parse_pools(self, content):
        """解析 Pool 配置"""
        # 使用更健壮的方式解析嵌套大括号
        pattern = r'ltm pool\s+(\S+)\s*\{'
        matches = list(re.finditer(pattern, content))
        
        for match in matches:
            name = match.group(1)
            start_pos = match.end() - 1
            
            # 找到匹配的结束大括号
            brace_count = 0
            end_pos = start_pos
            for j, char in enumerate(content[start_pos:]):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = start_pos + j + 1
                        break
            
            config = content[start_pos:end_pos]
            
            # 标准化 pool 名称
            if not name.startswith('/'):
                full_name = f'/Common/{name}'
            else:
                full_name = name
            
            pool_info = {
                'name': full_name,
                'short_name': name.split('/')[-1] if '/' in name else name,
                'monitor': self._extract_monitor(config),
                'members': self._extract_members(config),
                'load_balancing_mode': self._extract_value(config, 'load-balancing-mode', 'round-robin')
            }
            self.config['pools'][full_name] = pool_info
            # 同时用短名称存储，方便查找
            self.config['pools'][name.split('/')[-1] if '/' in name else name] = pool_info
    
    def _extract_monitor(self, config):
        """提取 monitor 配置"""
        pattern = r'^\s*monitor\s+([\w/\-_]+)'
        match = re.search(pattern, config, re.MULTILINE)
        if match:
            monitor = match.group(1).strip()
            if not monitor.startswith('/'):
                monitor = f'/Common/{monitor}'
            return monitor
        return ''
    
    def _parse_profiles(self, content):
        """解析 Profile 配置"""
        profile_types = [
            'client-ssl', 'server-ssl', 'http', 'tcp', 'udp', 'fastL4',
            'oneconnect', 'stream', 'rewrite', 'analytics', 'request-adapt',
            'response-adapt', 'statistics', 'ssl', 'persist'
        ]
        
        for ptype in profile_types:
            pattern = rf'ltm profile\s+{ptype}\s+(\S+)\s*\{{([^}}]+)\}}'
            matches = re.findall(pattern, content, re.DOTALL)
            
            for name, config in matches:
                if name not in self.SYSTEM_DEFAULTS['profiles']:
                    self.config['profiles'][f"{ptype}/{name}"] = {
                        'name': name,
                        'type': ptype,
                        'config': config.strip()
                    }
    
    def _parse_irules(self, content):
        """解析 iRule 配置"""
        pattern = r'ltm rule\s+(\S+)\s*\{([^}]+)\}'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for name, rule_content in matches:
            if name not in self.SYSTEM_DEFAULTS['irules']:
                # 分析 iRule 中引用的对象
                referenced_objects = self._analyze_irule_references(rule_content)
                
                self.config['irules'][name] = {
                    'name': name,
                    'content': rule_content.strip(),
                    'references': referenced_objects
                }
    
    def _parse_monitors(self, content):
        """解析 Monitor 配置"""
        pattern = r'ltm monitor\s+(\S+)\s+(\S+)\s*\{([^}]+)\}'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for mtype, name, config in matches:
            if name not in self.SYSTEM_DEFAULTS['monitors']:
                self.config['monitors'][f"{mtype}/{name}"] = {
                    'name': name,
                    'type': mtype,
                    'config': config.strip()
                }
    
    def _parse_nodes(self, content):
        """解析 Node 配置"""
        pattern = r'ltm node\s+(\S+)\s*\{([^}]+)\}'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for name, config in matches:
            self.config['nodes'][name] = {
                'name': name,
                'address': self._extract_value(config, 'address'),
                'monitor': self._extract_value(config, 'monitor')
            }
    
    def _parse_snats(self, content):
        """解析 SNAT 配置"""
        pattern = r'ltm snat\s+(\S+)\s*\{([^}]+)\}'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for name, config in matches:
            self.config['snats'][name] = {
                'name': name,
                'origins': self._extract_list(config, 'origins'),
                'translation': self._extract_value(config, 'translation')
            }
    
    def _parse_policies(self, content):
        """解析 Policy 配置"""
        pattern = r'ltm policy\s+(\S+)\s*\{([^}]+)\}'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for name, config in matches:
            self.config['policies'][name] = {
                'name': name,
                'controls': self._extract_list(config, 'controls'),
                'requires': self._extract_list(config, 'requires'),
                'rules': self._extract_policy_rules(config)
            }
    
    def _parse_datagroups(self, content):
        """解析 Data Group 配置"""
        pattern = r'ltm data-group\s+(?:internal|external)\s+(\S+)\s*\{([^}]+)\}'
        matches = re.findall(pattern, content, re.DOTALL)
        
        for name, config in matches:
            if name not in self.SYSTEM_DEFAULTS['datagroups']:
                self.config['datagroups'][name] = {
                    'name': name,
                    'type': 'internal' if 'records' in config else 'external',
                    'config': config.strip()
                }
    
    def _analyze_irule_references(self, irule_content):
        """分析 iRule 中引用的对象"""
        references = {
            'pools': [],
            'datagroups': [],
            'profiles': [],
            'nodes': [],
            'policies': []
        }
        
        # 匹配 pool 引用
        pool_matches = re.findall(r'pool\s+(\S+)', irule_content)
        references['pools'] = list(set(pool_matches))
        
        # 匹配 datagroup 引用
        dg_matches = re.findall(r'class\s+match\s+\S+\s+equals\s+(\S+)', irule_content)
        dg_matches += re.findall(r'\[class\s+lookup\s+(\S+)', irule_content)
        references['datagroups'] = list(set(dg_matches))
        
        return references
    
    def _extract_value(self, config, key, default=''):
        """提取配置项的值"""
        # 支持多行配置，匹配 key 后面的值（直到行尾或遇到另一个关键字）
        # 处理 /Common/pool_name 这样的格式
        pattern = rf'{key}\s+([\S/]+)'
        match = re.search(pattern, config)
        if match:
            value = match.group(1).strip()
            # 移除可能的注释
            if '#' in value:
                value = value.split('#')[0].strip()
            return value
        return default
    
    def _extract_list(self, config, key):
        """提取配置项的列表"""
        pattern = rf'{key}\s+\{{([^}}]+)\}}'
        match = re.search(pattern, config)
        if match:
            items = re.findall(r'(\S+)', match.group(1))
            return [item for item in items if item not in ['{', '}']]
        return []
    
    def _extract_members(self, config):
        """提取 pool members"""
        pattern = r'members\s*\{([^}]+)\}'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            members_text = match.group(1)
            # 匹配 member 定义
            member_pattern = r'(\S+:\d+)\s*\{([^}]*)\}'
            members = re.findall(member_pattern, members_text)
            return [{'name': m[0], 'config': m[1].strip()} for m in members]
        return []
    
    def _extract_policy_rules(self, config):
        """提取 policy rules"""
        # 简化处理，提取 rules 块
        pattern = r'rules\s*\{([^}]+)\}'
        match = re.search(pattern, config, re.DOTALL)
        if match:
            return [r.strip() for r in match.group(1).split('\n') if r.strip()]
        return []
    
    def find_unused_objects(self):
        """找出未被使用的对象"""
        unused = {
            'pools': [],
            'profiles': [],
            'irules': [],
            'monitors': [],
            'nodes': [],
            'snats': [],
            'policies': [],
            'datagroups': []
        }
        
        # 收集所有被引用的对象
        referenced_pools = set()
        referenced_profiles = set()
        referenced_irules = set()
        referenced_monitors = set()
        referenced_nodes = set()
        referenced_policies = set()
        referenced_datagroups = set()
        
        # 从 Virtual Server 收集引用
        for vs_name, vs_info in self.config['virtuals'].items():
            if vs_info['pool']:
                referenced_pools.add(vs_info['pool'])
            for profile in vs_info['profiles']:
                referenced_profiles.add(profile)
            for rule in vs_info['rules']:
                referenced_irules.add(rule)
            for policy in vs_info['policies']:
                referenced_policies.add(policy)
        
        # 从 Pool 收集引用（monitor、node）
        for pool_name, pool_info in self.config['pools'].items():
            if pool_info['monitor']:
                referenced_monitors.add(pool_info['monitor'])
            for member in pool_info['members']:
                node_name = member['name'].split(':')[0]
                referenced_nodes.add(node_name)
        
        # 从 iRule 收集引用
        for rule_name, rule_info in self.config['irules'].items():
            for pool in rule_info['references']['pools']:
                referenced_pools.add(pool)
            for dg in rule_info['references']['datagroups']:
                referenced_datagroups.add(dg)
        
        # 标准化引用的 pool 名称
        normalized_referenced_pools = set()
        for pool in referenced_pools:
            if not pool.startswith('/'):
                normalized_referenced_pools.add(f'/Common/{pool}')
            else:
                normalized_referenced_pools.add(pool)
            # 同时添加短名称
            normalized_referenced_pools.add(pool.split('/')[-1] if '/' in pool else pool)
        
        # 找出未使用的对象
        checked_pools = set()
        for pool_name in self.config['pools']:
            # 避免重复检查（因为 pools 可能同时存储了长短名称）
            if pool_name in checked_pools:
                continue
            checked_pools.add(pool_name)
            
            # 标准化 pool 名称进行检查
            pool_short = pool_name.split('/')[-1] if '/' in pool_name else pool_name
            pool_full = f'/Common/{pool_short}' if not pool_name.startswith('/') else pool_name
            
            if pool_full not in normalized_referenced_pools and pool_short not in normalized_referenced_pools:
                # 只记录完整名称
                if pool_name not in unused['pools']:
                    unused['pools'].append(pool_full)
        
        for profile_name in self.config['profiles']:
            profile_short = profile_name.split('/')[-1]
            if profile_short not in referenced_profiles:
                unused['profiles'].append(profile_name)
        
        for rule_name in self.config['irules']:
            if rule_name not in referenced_irules:
                unused['irules'].append(rule_name)
        
        for monitor_name in self.config['monitors']:
            monitor_short = monitor_name.split('/')[-1]
            if monitor_short not in referenced_monitors:
                unused['monitors'].append(monitor_name)
        
        for node_name in self.config['nodes']:
            if node_name not in referenced_nodes:
                unused['nodes'].append(node_name)
        
        for policy_name in self.config['policies']:
            if policy_name not in referenced_policies:
                unused['policies'].append(policy_name)
        
        for dg_name in self.config['datagroups']:
            if dg_name not in referenced_datagroups:
                unused['datagroups'].append(dg_name)
        
        return unused
    
    def generate_virtual_server_table(self):
        """生成 Virtual Server 配置表"""
        data = []
        
        for vs_name, vs_info in self.config['virtuals'].items():
            # 格式化 pool 显示
            pool_display = vs_info['pool']
            if pool_display:
                # 显示短名称，但保留完整路径
                if '/' in pool_display:
                    pool_short = pool_display.split('/')[-1]
                    pool_display = f"{pool_short} ({pool_display})"
            else:
                pool_display = 'None'
            
            # 格式化 profiles 显示
            profiles_display = ', '.join(vs_info['profiles']) if vs_info['profiles'] else 'None'
            
            # 格式化 irules 显示
            irules_display = ', '.join(vs_info['rules']) if vs_info['rules'] else 'None'
            
            # 格式化 policies 显示
            policies_display = ', '.join(vs_info['policies']) if vs_info['policies'] else 'None'
            
            # 格式化 persistence 显示
            persistence_display = 'None'
            if vs_info['persist']:
                persist_strs = []
                for p in vs_info['persist']:
                    if isinstance(p, dict):
                        # 结构化数据
                        default_mark = ' [默认]' if p.get('default') == 'yes' else ''
                        persist_strs.append(f"{p['profile_short']}{default_mark} ({p['type']})")
                    else:
                        # 字符串数据（兼容旧格式）
                        persist_strs.append(p)
                persistence_display = '\n'.join(persist_strs)
            
            row = {
                'Virtual Server': vs_name,
                'Destination': vs_info['destination'] or 'N/A',
                'IP Protocol': vs_info['ip_protocol'] or 'tcp',
                'Pool': pool_display,
                'Profiles': profiles_display,
                'iRules': irules_display,
                'Policies': policies_display,
                'SNAT': vs_info['snat'] or 'None',
                'Persistence': persistence_display,
                'Status': 'Disabled' if vs_info['disabled'] else 'Enabled'
            }
            data.append(row)
        
        return pd.DataFrame(data)
    
    def generate_unused_objects_table(self, unused):
        """生成未使用对象表"""
        data = []
        
        for obj_type, objects in unused.items():
            for obj_name in objects:
                data.append({
                    'Object Type': obj_type,
                    'Object Name': obj_name,
                    'Recommendation': 'Can be deleted' if obj_type != 'nodes' else 'Check if used by other pools'
                })
        
        return pd.DataFrame(data)
    
    def generate_summary(self):
        """生成配置汇总"""
        summary = {
            'Object Type': [],
            'Total Count': [],
            'Custom Count': [],
            'System Default': []
        }
        
        object_types = [
            ('Virtual Servers', 'virtuals'),
            ('Pools', 'pools'),
            ('Profiles', 'profiles'),
            ('iRules', 'irules'),
            ('Monitors', 'monitors'),
            ('Nodes', 'nodes'),
            ('SNATs', 'snats'),
            ('Policies', 'policies'),
            ('Data Groups', 'datagroups')
        ]
        
        for type_name, key in object_types:
            count = len(self.config[key])
            summary['Object Type'].append(type_name)
            summary['Total Count'].append(count)
            summary['Custom Count'].append(count)  # 已经排除了系统默认
            summary['System Default'].append(0)
        
        return pd.DataFrame(summary)
    
    def export_to_excel(self, unused):
        """导出到 Excel"""
        output_file = self.output_dir / 'f5_ucs_analysis.xlsx'
        
        print(f"正在导出到 Excel: {output_file}")
        
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # Virtual Server 表
            vs_df = self.generate_virtual_server_table()
            vs_df.to_excel(writer, sheet_name='Virtual Servers', index=False)
            
            # 未使用对象表
            unused_df = self.generate_unused_objects_table(unused)
            unused_df.to_excel(writer, sheet_name='Unused Objects', index=False)
            
            # 配置汇总
            summary_df = self.generate_summary()
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Pool 详情
            pool_data = []
            for pool_name, pool_info in self.config['pools'].items():
                pool_data.append({
                    'Pool Name': pool_name,
                    'Monitor': pool_info['monitor'] or 'None',
                    'LB Mode': pool_info['load_balancing_mode'],
                    'Members': len(pool_info['members']),
                    'Member List': ', '.join([m['name'] for m in pool_info['members']])
                })
            if pool_data:
                pd.DataFrame(pool_data).to_excel(writer, sheet_name='Pools', index=False)
            
            # iRule 详情
            irule_data = []
            for rule_name, rule_info in self.config['irules'].items():
                irule_data.append({
                    'iRule Name': rule_name,
                    'Referenced Pools': ', '.join(rule_info['references']['pools']) or 'None',
                    'Referenced DataGroups': ', '.join(rule_info['references']['datagroups']) or 'None',
                    'Line Count': len(rule_info['content'].split('\n'))
                })
            if irule_data:
                pd.DataFrame(irule_data).to_excel(writer, sheet_name='iRules', index=False)
            
            # Persistence 详情
            persistence_data = []
            for vs_name, vs_info in self.config['virtuals'].items():
                if vs_info['persist']:
                    for p in vs_info['persist']:
                        if isinstance(p, dict):
                            persistence_data.append({
                                'Virtual Server': vs_name,
                                'Profile Name': p['profile'],
                                'Profile Short': p['profile_short'],
                                'Partition': p['partition'],
                                'Type': p['type'],
                                'Default': p['default']
                            })
            if persistence_data:
                pd.DataFrame(persistence_data).to_excel(writer, sheet_name='Persistence', index=False)
        
        print(f"Excel 文件已生成: {output_file}")
        return output_file
    
    def export_dependencies_json(self):
        """导出依赖关系到 JSON"""
        output_file = self.output_dir / 'dependencies.json'
        
        # 将 set 转换为 list 以便 JSON 序列化
        references_list = {}
        for key, value in self.references.items():
            references_list[key] = [list(item) for item in value]
        
        dependencies = {
            'virtual_servers': {},
            'references': references_list
        }
        
        for vs_name, vs_info in self.config['virtuals'].items():
            dependencies['virtual_servers'][vs_name] = {
                'pool': vs_info['pool'],
                'profiles': vs_info['profiles'],
                'irules': vs_info['rules'],
                'policies': vs_info['policies']
            }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(dependencies, f, indent=2, ensure_ascii=False)
        
        print(f"依赖关系 JSON 已生成: {output_file}")
        return output_file
    
    def run(self):
        """运行分析"""
        print("=" * 60)
        print("F5 UCS 配置分析工具")
        print("=" * 60)
        
        # 解压 UCS
        config_file = self.extract_ucs()
        
        # 解析配置
        self.parse_config(config_file)
        
        # 找出未使用的对象
        unused = self.find_unused_objects()
        
        # 生成报告
        print("\n配置统计:")
        print(f"  Virtual Servers: {len(self.config['virtuals'])}")
        print(f"  Pools: {len(self.config['pools'])}")
        print(f"  Profiles: {len(self.config['profiles'])}")
        print(f"  iRules: {len(self.config['irules'])}")
        print(f"  Monitors: {len(self.config['monitors'])}")
        print(f"  Nodes: {len(self.config['nodes'])}")
        print(f"  SNATs: {len(self.config['snats'])}")
        print(f"  Policies: {len(self.config['policies'])}")
        print(f"  Data Groups: {len(self.config['datagroups'])}")
        
        print("\n未使用对象统计:")
        for obj_type, objects in unused.items():
            if objects:
                print(f"  {obj_type}: {len(objects)}")
        
        # 导出到 Excel
        excel_file = self.export_to_excel(unused)
        
        # 导出依赖关系
        json_file = self.export_dependencies_json()
        
        print("\n" + "=" * 60)
        print("分析完成!")
        print(f"输出目录: {self.output_dir}")
        print(f"Excel 报告: {excel_file}")
        print(f"JSON 依赖: {json_file}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description='F5 UCS 配置分析工具')
    parser.add_argument('-u', '--ucs', required=True, help='UCS 文件路径')
    parser.add_argument('-o', '--output', default='./f5_analysis_output', help='输出目录')
    
    args = parser.parse_args()
    
    analyzer = F5UCSAnalyzer(args.ucs, args.output)
    analyzer.run()


if __name__ == '__main__':
    main()
