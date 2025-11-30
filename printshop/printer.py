# 打印相关功能
# ...existing code...
import os
import subprocess
from PIL import Image
from PyPDF2 import PdfReader

def print_file(filepath, printer_name=None):
	"""
	根据文件类型自动选择打印方式。
	支持 PDF 和图片（jpg/png/bmp等）。
	可指定打印机名称。
	"""
	ext = os.path.splitext(filepath)[1].lower()
	if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
		return print_image(filepath, printer_name)
	elif ext == '.pdf':
		return print_pdf(filepath, printer_name)
	else:
		raise ValueError('暂不支持的文件类型: ' + ext)

def print_image(image_path, printer_name=None):
	"""
	使用 Windows 的 print 命令打印图片，可指定打印机。
	"""
	try:
		# 使用 mspaint 打印并指定打印机
		if printer_name:
			# 通过printui命令获取打印机全名
			# 直接用mspaint /pt 文件 "打印机名"，部分系统可用
			subprocess.run(['mspaint', '/pt', image_path, printer_name], check=True)
		else:
			subprocess.run(['mspaint', '/pt', image_path], check=True)
		return True
	except Exception as e:
		print(f"打印图片失败: {e}")
		return False

def print_pdf(pdf_path, printer_name=None):
	"""
	用 Acrobat Reader 或 Edge 打印 PDF，可指定打印机。
	"""
	try:
		acro_paths = [
			r'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe',
			r'C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe',
		]
		for acro in acro_paths:
			if os.path.exists(acro):
				if printer_name:
					subprocess.run([acro, '/t', pdf_path, printer_name], check=True)
				else:
					subprocess.run([acro, '/t', pdf_path], check=True)
				return True
		edge_path = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
		if os.path.exists(edge_path):
			subprocess.run([edge_path, '/print', pdf_path], check=True)
			return True
		print("未检测到 Acrobat 或 Edge，无法自动打印 PDF。请手动打印。")
		return False
	except Exception as e:
		print(f"打印PDF失败: {e}")
		return False

