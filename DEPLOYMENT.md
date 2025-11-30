# 打印店管理系统部署指南

## 系统要求

- Python 3.8+
- pip
- SQLite
- 打印机设备(可选)

## 安装步骤

1. 克隆代码库:
```bash
git clone https://github.com/yourusername/printshop.git
cd printshop
```

2. 创建虚拟环境(推荐):
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. 安装依赖:
```bash
pip install -r requirements.txt
```

## 配置

1. 复制示例配置文件:
```bash
cp .env.example .env
```

2. 编辑.env文件:
```ini
SECRET_KEY=your_random_secret_key
DATABASE_URI=sqlite:///printshop.db
DEBUG=False  # 生产环境设为False
```

## 生产环境部署

### 使用Gunicorn + Nginx (Linux)

1. 安装Gunicorn:
```bash
pip install gunicorn
```

2. 运行Gunicorn:
```bash
gunicorn -w 4 -b 127.0.0.1:8000 "printshop.remote:app"
```

3. Nginx配置示例:
```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 常见问题

### 1. 无法打印文件
- 确保打印机已连接并配置正确
- 检查文件格式是否支持(PDF, JPG, PNG等)

### 2. 数据库问题
- 删除printshop.db文件后重新启动应用会自动创建新数据库

### 3. 端口冲突
- 修改remote.py中的端口号或停止占用端口的进程
