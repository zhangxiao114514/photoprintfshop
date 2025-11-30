# 打印相关功能
# ...existing code...
import os
import subprocess
from PIL import Image
from PyPDF2 import PdfReader

def print_office(filepath, printer_name=None):
    """
    使用Windows默认程序打印Office文档(PPT/DOC)
    """
    try:
        if printer_name:
            # 使用Windows的printto命令打印并指定打印机
            subprocess.run(['start', '/wait', '""', filepath, '/p', printer_name], shell=True)
        else:
            subprocess.run(['start', '/wait', '""', filepath, '/p'], shell=True)
        return True
    except Exception as e:
        print(f"打印Office文档失败: {e}")
        return False

def count_code_lines(filepath):
    """计算代码文件的行数"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return sum(1 for _ in f)
    except:
        return 1  # 默认按1行计算

def print_file(filepath, printer_name=None):
    """
    根据文件类型自动选择打印方式。
    支持 PDF、图片(jpg/png/bmp等)、Office文档(ppt/doc)和代码文件(cpp/py/txt)。
    可指定打印机名称。
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']:
        return print_image(filepath, printer_name)
    elif ext == '.pdf':
        return print_pdf(filepath, printer_name)
    elif ext in ['.ppt', '.pptx', '.doc', '.docx']:
        return print_office(filepath, printer_name)
    elif ext in ['.cpp', '.py', '.txt']:
        # 代码文件使用记事本打印
        try:
            if printer_name:
                subprocess.run(['notepad', '/p', filepath, printer_name], shell=True)
            else:
                subprocess.run(['notepad', '/p', filepath], shell=True)
            return True
        except Exception as e:
            print(f"打印代码文件失败: {e}")
            return False
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
