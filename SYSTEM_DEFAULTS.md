# F5 UCS 分析工具 - 系统默认对象列表

## 默认 Profiles (自动排除)

### 协议 Profiles
- tcp
- udp
- sctp
- fastL4
- fasthttp

### HTTP 相关
- http
- https

### SSL 相关
- clientssl
- serverssl
- ssl

### 连接管理
- oneconnect
- stream

### 其他
- statistics
- analytics
- request-adapt
- response-adapt
- rewrite

### Persistence Profiles
- source_addr
- cookie
- dest_addr
- hash
- msrdp
- sip_info

## 默认 Monitors (自动排除)

### 基础监控
- gateway_icmp
- icmp
- tcp
- tcp_half_open
- udp

### 应用监控
- http
- https
- ftp
- pop3
- smtp

### 数据库监控
- mssql
- mysql
- oracle
- postgresql

### 其他
- snmp_dca
- snmp_dca_base
- radius
- ldap
- imap

## 系统 iRules (自动排除)

- _sys_auth_ssl_cc_ldap
- _sys_auth_ssl_crldp
- _sys_auth_ssl_ocsp
- _sys_auth_ssl_ldap
- _sys_https_redirect
- _sys_APM_Websocket
- _sys_APM_activesync
- _sys_APM_ExchangeSupport_helper
- _sys_APM_ExchangeSupport_main
- _sys_APM_owa
- _sys_APM_sharepoint
- _sys_APM_tmpl_info
- _sys_APM_activesync_v2

## 说明

这些对象会在分析时自动排除，不会出现在"未使用对象"报告中。
如果需要添加更多系统默认对象，请修改 f5_ucs_analyzer.py 中的 SYSTEM_DEFAULTS 字典。
