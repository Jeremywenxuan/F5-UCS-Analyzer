# F5 UCS 配置分析工具

## 📋 功能说明

这个工具可以分析 F5 UCS 配置文件，帮助你：

1. **📊 生成 Virtual Server 配置表** - 显示每个 VS 调用的 Pool、Profile、iRule、Policy 等
2. **🗑️ 找出未使用的配置对象** - 识别可以删除的冗余配置（自动排除 F5 系统自带对象）
3. **📈 生成配置汇总报告** - 统计各类配置对象的数量
4. **🔗 导出依赖关系** - JSON 格式的配置依赖关系

## 🔧 支持的配置对象

- ✅ Virtual Server (VS)
- ✅ Pool / Pool Member
- ✅ Profile (所有类型: tcp, http, client-ssl, server-ssl, 等)
- ✅ iRule
- ✅ Monitor
- ✅ Node
- ✅ SNAT
- ✅ Policy
- ✅ Data Group (Internal/External)

## 📦 自动排除的系统默认对象

工具会自动识别并排除 F5 系统自带的默认配置，包括：
- 默认 Profiles: tcp, http, clientssl, serverssl, fastL4 等
- 默认 Monitors: gateway_icmp, tcp, http, https 等
- 系统 iRules: _sys_* 开头的规则

## 🚀 使用方法

### 1. 激活虚拟环境

```bash
cd F5-UCS-Analyzer
.\venv\Scripts\activate
```

### 2. 运行分析工具

```bash
python f5_ucs_analyzer.py -u <ucs文件路径> -o <输出目录>
```

**示例:**
```bash
python f5_ucs_analyzer.py -u C:\backup\config.ucs -o ./analysis_result
```

## 📁 输出文件

运行后会生成以下文件：

### Excel 报告 (`f5_ucs_analysis.xlsx`)
包含多个工作表：

1. **Virtual Servers** - VS 配置详情
   - Virtual Server 名称
   - Destination IP:Port
   - 调用的 Pool
   - 调用的 Profiles
   - 调用的 iRules
   - 调用的 Policies
   - SNAT 配置
   - Persistence 配置
   - 状态 (Enabled/Disabled)

2. **Unused Objects** - 未使用的对象列表
   - 对象类型
   - 对象名称
   - 删除建议

3. **Summary** - 配置汇总统计
   - 各类对象的总数
   - 自定义对象数量

4. **Pools** - Pool 详情
   - Pool 名称
   - Monitor 配置
   - 负载均衡模式
   - Member 列表

5. **iRules** - iRule 详情
   - iRule 名称
   - 引用的 Pools
   - 引用的 DataGroups
   - 代码行数

### JSON 文件 (`dependencies.json`)
- Virtual Server 的依赖关系
- 可用于进一步分析或可视化

## 💡 使用场景

### 场景 1: 清理冗余配置
```bash
python f5_ucs_analyzer.py -u config.ucs -o cleanup_report
```
查看 `Unused Objects` 工作表，安全删除未使用的对象。

### 场景 2: 文档化配置
```bash
python f5_ucs_analyzer.py -u config.ucs -o documentation
```
使用 `Virtual Servers` 工作表作为配置文档。

### 场景 3: 配置审计
```bash
python f5_ucs_analyzer.py -u config.ucs -o audit
```
检查所有 VS 的配置是否规范，是否有未使用的对象。

## ⚠️ 注意事项

1. **Node 对象**: 工具会标记未被 Pool 引用的 Node，但请确认这些 Node 确实不再需要后再删除。

2. **iRule 引用**: 工具会分析 iRule 代码中的 pool、class (datagroup) 引用，但复杂的动态引用可能无法完全识别。

3. **系统对象**: 工具已内置常见系统默认对象列表，但可能不包含所有版本的所有默认对象。如有误报，请反馈。

## 🔧 故障排除

### 问题: "在 UCS 文件中未找到 bigip.conf"
- 确保 UCS 文件完整且未损坏
- 检查 UCS 文件是否为标准的 .ucs 或 .tar.gz 格式

### 问题: Excel 文件无法打开
- 确保已安装 Microsoft Excel 或兼容软件
- 检查输出目录是否有写入权限

## 📝 更新日志

### v1.0.0 (2026-03-12)
- 初始版本
- 支持 VS、Pool、Profile、iRule、Monitor、Node、SNAT、Policy、DataGroup 分析
- 自动生成 Excel 报告和 JSON 依赖关系

## 👤 作者

Created by Jeremy
