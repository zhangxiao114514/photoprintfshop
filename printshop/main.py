# 打印店系统主入口
import threading
from gui import main as gui_main
from remote import app, run_server

def start_remote_server():
    # 确保在子线程中创建新的应用上下文
    with app.app_context():
        run_server(port=5000)

if __name__ == "__main__":
    # 启动远程打印服务线程
    server_thread = threading.Thread(target=start_remote_server, daemon=True)
    server_thread.start()
    
    # 启动GUI主界面
    gui_main()
