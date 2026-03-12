#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
F5 UCS 分析工具 - Web 服务
提供前端界面上传 UCS 文件并分析
"""

import os
import sys
import json
import uuid
import threading
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

# 导入分析器
from f5_ucs_analyzer import F5UCSAnalyzer

app = Flask(__name__)
CORS(app)

# 配置
UPLOAD_FOLDER = Path('./uploads')
RESULT_FOLDER = Path('./results')
ALLOWED_EXTENSIONS = {'ucs', 'tar', 'gz', 'zip'}

UPLOAD_FOLDER.mkdir(exist_ok=True)
RESULT_FOLDER.mkdir(exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULT_FOLDER'] = RESULT_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 最大 500MB

# 存储分析任务状态
analysis_tasks = {}


def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """主页"""
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """上传 UCS 文件"""
    if 'file' not in request.files:
        return jsonify({'error': '没有文件'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400
    
    if file and allowed_file(file.filename):
        # 生成唯一任务 ID
        task_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        saved_filename = f"{task_id}_{timestamp}_{filename}"
        
        file_path = UPLOAD_FOLDER / saved_filename
        file.save(file_path)
        
        # 记录任务
        analysis_tasks[task_id] = {
            'id': task_id,
            'filename': filename,
            'saved_path': str(file_path),
            'status': 'uploaded',
            'created_at': datetime.now().isoformat(),
            'result_path': None,
            'error': None
        }
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'filename': filename,
            'message': '文件上传成功'
        })
    
    return jsonify({'error': '不支持的文件类型'}), 400


@app.route('/api/analyze/<task_id>', methods=['POST'])
def analyze_file(task_id):
    """开始分析 UCS 文件"""
    if task_id not in analysis_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = analysis_tasks[task_id]
    
    if task['status'] == 'analyzing':
        return jsonify({'error': '任务正在分析中'}), 400
    
    if task['status'] == 'completed':
        return jsonify({'error': '任务已完成'}), 400
    
    # 在后台线程中运行分析
    def run_analysis():
        try:
            task['status'] = 'analyzing'
            
            # 创建输出目录
            output_dir = RESULT_FOLDER / task_id
            output_dir.mkdir(exist_ok=True)
            
            # 运行分析
            analyzer = F5UCSAnalyzer(task['saved_path'], str(output_dir))
            analyzer.run()
            
            # 更新任务状态
            task['status'] = 'completed'
            task['result_path'] = str(output_dir)
            task['completed_at'] = datetime.now().isoformat()
            
        except Exception as e:
            task['status'] = 'error'
            task['error'] = str(e)
    
    thread = threading.Thread(target=run_analysis)
    thread.start()
    
    return jsonify({
        'success': True,
        'task_id': task_id,
        'status': 'analyzing',
        'message': '分析已开始'
    })


@app.route('/api/status/<task_id>', methods=['GET'])
def get_status(task_id):
    """获取任务状态"""
    if task_id not in analysis_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = analysis_tasks[task_id]
    
    response = {
        'task_id': task_id,
        'status': task['status'],
        'filename': task['filename'],
        'created_at': task['created_at']
    }
    
    if task['status'] == 'completed':
        response['completed_at'] = task['completed_at']
        response['result_path'] = task['result_path']
    elif task['status'] == 'error':
        response['error'] = task['error']
    
    return jsonify(response)


@app.route('/api/results/<task_id>', methods=['GET'])
def get_results(task_id):
    """获取分析结果"""
    if task_id not in analysis_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = analysis_tasks[task_id]
    
    if task['status'] != 'completed':
        return jsonify({'error': '分析尚未完成'}), 400
    
    result_dir = Path(task['result_path'])
    
    # 检查文件是否存在
    excel_file = result_dir / 'f5_ucs_analysis.xlsx'
    json_file = result_dir / 'dependencies.json'
    
    results = {
        'task_id': task_id,
        'files': {}
    }
    
    if excel_file.exists():
        results['files']['excel'] = {
            'name': 'f5_ucs_analysis.xlsx',
            'size': excel_file.stat().st_size,
            'download_url': f'/api/download/{task_id}/excel'
        }
    
    if json_file.exists():
        results['files']['json'] = {
            'name': 'dependencies.json',
            'size': json_file.stat().st_size,
            'download_url': f'/api/download/{task_id}/json'
        }
    
    return jsonify(results)


@app.route('/api/download/<task_id>/<file_type>', methods=['GET'])
def download_file(task_id, file_type):
    """下载分析结果文件"""
    if task_id not in analysis_tasks:
        return jsonify({'error': '任务不存在'}), 404
    
    task = analysis_tasks[task_id]
    
    if task['status'] != 'completed':
        return jsonify({'error': '分析尚未完成'}), 400
    
    result_dir = Path(task['result_path'])
    
    if file_type == 'excel':
        file_path = result_dir / 'f5_ucs_analysis.xlsx'
        if file_path.exists():
            return send_file(file_path, as_attachment=True, download_name='f5_ucs_analysis.xlsx')
    elif file_type == 'json':
        file_path = result_dir / 'dependencies.json'
        if file_path.exists():
            return send_file(file_path, as_attachment=True, download_name='dependencies.json')
    
    return jsonify({'error': '文件不存在'}), 404


@app.route('/api/tasks', methods=['GET'])
def list_tasks():
    """列出所有任务"""
    tasks = []
    for task_id, task in analysis_tasks.items():
        tasks.append({
            'task_id': task_id,
            'filename': task['filename'],
            'status': task['status'],
            'created_at': task['created_at']
        })
    
    # 按创建时间排序
    tasks.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({'tasks': tasks[:10]})  # 只返回最近 10 个


@app.route('/api/cleanup', methods=['POST'])
def cleanup_old_files():
    """清理旧的文件"""
    try:
        # 清理上传文件
        for file in UPLOAD_FOLDER.iterdir():
            if file.is_file():
                file.unlink()
        
        # 清理结果文件
        for folder in RESULT_FOLDER.iterdir():
            if folder.is_dir():
                for file in folder.iterdir():
                    file.unlink()
                folder.rmdir()
        
        # 清空任务列表
        analysis_tasks.clear()
        
        return jsonify({'success': True, 'message': '清理完成'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("F5 UCS 分析工具 - Web 服务")
    print("=" * 60)
    print(f"上传目录: {UPLOAD_FOLDER.absolute()}")
    print(f"结果目录: {RESULT_FOLDER.absolute()}")
    print("=" * 60)
    print("访问地址: http://localhost:5000")
    print("=" * 60)
    
    # 运行 Flask 服务
    app.run(host='0.0.0.0', port=5000, debug=True)
