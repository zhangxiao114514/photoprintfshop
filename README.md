# 打印店管理系统

一个基于Flask的打印店管理系统，提供用户认证、文件打印、余额管理等功能。

## 功能特性

- 用户注册/登录/密码重置
- 双因素认证(2FA)支持
- 文件上传和打印管理
- 兑换码充值系统
- 打印历史记录
- 本地GUI和Web界面

## 技术栈

- 后端: Python, Flask, SQLAlchemy
- 前端: Bootstrap, Jinja2模板
- 数据库: SQLite
- 安全: CSRF保护, 密码哈希
- 其他: pyotp(2FA), qrcode

## 快速开始

1. 克隆仓库:
```bash
git clone https://github.com/yourusername/printshop.git
cd printshop
```

2. 安装依赖:
```bash
pip install -r requirements.txt
```

3. 运行应用:
```bash
python printshop/main.py
```

4. 访问 `http://localhost:5000`

## 配置

复制 `.env.example` 并重命名为 `.env`，然后修改配置:
```
SECRET_KEY=your_secret_key
DATABASE_URI=sqlite:///printshop.db
```

## API文档

### 用户认证
- `POST /login` - 用户登录
- `POST /register` - 用户注册
- `POST /forgot_password` - 密码重置请求
- `POST /reset_password/<token>` - 重置密码

### 打印功能
- `POST /print` - 提交打印任务

[查看完整API文档](API.md)
