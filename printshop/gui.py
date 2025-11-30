# Tkinter 图形界面
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import printer

PRINT_PASSWORD = "123456"  # 可修改为你想要的密码
EPSON_PRINTER_NAME = "EPSON"  # Epson打印机名称关键字

def select_and_print():
	# 密码校验
	pwd = simpledialog.askstring("密码验证", "请输入打印密码：", show='*')
	if pwd != PRINT_PASSWORD:
		messagebox.showerror("错误", "密码错误！")
		return
	file_path = filedialog.askopenfilename(title="选择要打印的文件", filetypes=[
		("支持的文件", ".pdf .jpg .jpeg .png .bmp .gif"),
		("所有文件", "*.*")
	])
	if not file_path:
		return
	# 打印时指定Epson打印机
	try:
		success = printer.print_file(file_path, printer_name=EPSON_PRINTER_NAME)
		if success:
			messagebox.showinfo("成功", "打印任务已发送！")
		else:
			messagebox.showerror("失败", "打印失败，请检查打印机连接。")
	except Exception as e:
		messagebox.showerror("异常", str(e))

def main():
	root = tk.Tk()
	root.title("打印店系统 - 本地打印")
	root.geometry("400x200")
	btn = tk.Button(root, text="选择文件并打印", command=select_and_print, font=("微软雅黑", 16))
	btn.pack(expand=True)
	root.mainloop()

