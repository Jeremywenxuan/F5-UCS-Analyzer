# F5 UCS 配置分析工具 - Web 版

## 🎉 新增功能

现在支持通过 Web 界面上传 UCS 文件并分析！

## 📁 项目结构

```
F5-UCS-Analyzer/
├── venv/                      # Python 虚拟环境
├── templates/
│   └── index.html            # Web 前端页面
├── uploads/                   # 上传文件存储目录
├── results/                   # 分析结果存储目录
├── f5_ucs_analyzer.py        # 核心分析模块
├── web_server.py             # Flask Web 服务
├── start_web.bat             # Web 服务启动脚本
├── analyze_ucs.bat           # 命令行分析脚本
└── README.md                 # 使用说明
```

## 🚀 快速开始

### 方式 1: Web 界面（推荐）

1. **启动 Web 服务**
   ```bash
   cd E:\ForOpenClaw\Codeing\F5\F5-UCS-Analyzer
   start_web.bat
   ```

2. **打开浏览器访问**
   ```
   http://localhost:5000
   ```

3. **使用步骤**
   - 点击上传区域或拖拽 UCS 文件
   - 等待文件上传完成
   - 点击"开始分析"按钮
   - 等待分析完成
   - 下载 Excel 报告和 JSON 数据

### 方式 2: 命令行

```bash
analyze_ucs.bat C:\path\to\config.ucs
```

## 🌐 Web 界面功能

### 📤 文件上传
- 支持点击上传或拖拽上传
- 支持 .ucs, .tar.gz, .zip 格式
- 最大支持 500MB

### 📊 实时进度
- 显示分析进度条
- 实时日志输出
- 状态自动刷新

### 📥 结果下载
- Excel 完整报告
- JSON 依赖关系数据

## 📊 分析报告内容

### Excel 报告包含以下工作表：

1. **Virtual Servers** - VS 配置详情
   - VS 名称、Destination
   - 调用的 Pool、Profile、iRule、Policy
   - SNAT 和 Persistence 配置
   - 状态信息

2. **Unused Objects** - 未使用对象
   - 可删除的 Pool、Profile、iRule 等
   - 系统默认对象已自动排除

3. **Summary** - 配置汇总
   - 各类对象数量统计

4. **Pools** - Pool 详情
   - Pool 配置和 Member 列表

5. **iRules** - iRule 详情
   - iRule 代码分析
   - 引用的对象列表

## 🔧 系统要求

- Windows 10/11
- Python 3.8+
- 浏览器（Chrome、Edge、Firefox 等）

## 📝 使用示例

### 示例 1: 清理冗余配置
1. 从 F5 设备导出 UCS 备份文件
2. 上传到 Web 界面
3. 运行分析
4. 查看 "Unused Objects" 工作表
5. 安全删除未使用的对象

### 示例 2: 文档化配置
1. 上传生产环境 UCS 文件
2. 分析完成后下载 Excel
3. 使用 "Virtual Servers" 工作表作为配置文档

### 示例 3: 配置审计
1. 定期导出 UCS 文件
2. 使用工具分析
3. 对比历史报告
4. 发现配置变更和异常

## ⚠️ 注意事项

1. **文件大小**: 最大支持 500MB，超大 UCS 文件可能需要更长时间

2. **Node 对象**: 工具会标记未被 Pool 引用的 Node，但请确认这些 Node 确实不再需要后再删除

3. **iRule 引用**: 工具会分析 iRule 代码中的 pool、datagroup 引用，但复杂的动态引用可能无法完全识别

4. **系统对象**: 已内置常见系统默认对象列表，但可能不包含所有版本的所有默认对象

## 🔍 故障排除

### Web 服务无法启动
- 检查虚拟环境是否存在
- 检查端口 5000 是否被占用
- 查看命令行错误信息

### 文件上传失败
- 检查文件大小是否超过 500MB
- 检查文件格式是否正确
- 检查 uploads 目录是否有写入权限

### 分析失败
- 确保 UCS 文件完整且未损坏
- 检查 UCS 文件是否为标准格式
- 查看日志输出获取详细错误信息

## 🔄 更新日志

### v1.1.0 (2026-03-12)
- ✅ 新增 Web 界面
- ✅ 支持拖拽上传
- ✅ 实时进度显示
- ✅ 在线下载结果

### v1.0.0 (2026-03-12)
- ✅ 初始版本
- ✅ 支持 UCS 文件分析
- ✅ 生成 Excel 报告
- ✅ 识别未使用对象

## 👤 作者

Created by OpenClaw Assistant
