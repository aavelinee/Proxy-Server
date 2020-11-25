from rwlock import RWLock
import json
import socket
import sys
import threading
import datetime
import time
import ssl
import base64

cache = {}
cache_rw_lock = RWLock()
accounting_rw_lock = threading.Lock()

def write_log(log_msg):
	if not log_file == None:
		current_time = (time.strftime("[%d/%b/%Y:%H:%M:%S]", time.gmtime()))
		log_lock.acquire()
		f = open(log_file,"a")
		msg = current_time + log_msg + "\n"
		f.write(msg)
		f.close()
		log_lock.release()

def find_nth(str, delim, n):
	parts = str.split(delim, n + 1)
	if len(parts) <= n + 1:
		return -1
	return len(str) - len(parts[-1]) - len(delim)


class config():
	def __init__(self):
		f = open("config.json")
		self.config = json.loads(f.read())

	def get_port(self):
		return self.config["port"]

	def get_privacy(self):
		if self.config["privacy"]["enable"] == True:
			return self.config["privacy"]["userAgent"]
		else:
			return None
	def get_cache_size(self):
		if self.config["caching"]["enable"] == True:
			return self.config["caching"]["size"]
		else:
			return None
	def get_logging(self):
		if self.config["logging"]["enable"] == True:
			return self.config["logging"]["logFile"]
		else:
			return None

	def get_restriction(self):
		if self.config["restriction"]["enable"] == True:
			return self.config["restriction"]["targets"]
		else:
			return None

	def get_accounting(self):
		return self.config["accounting"]["users"]

	def get_injection(self):
		if self.config["HTTPInjection"]["enable"] == True:
			return self.config["HTTPInjection"]["post"]["body"]
		else:
			return None
	

class mail_telnet():
	def __init__(self, mail_content, admin_user_pass_filename):
		self.mail_content = mail_content
		self.admin_user_pass_filename = admin_user_pass_filename

	def run(self):
		server = "smtp.gmail.com"
		port = 465

		client_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# wrapping for securing and for https
		wrapped_client_proxy = ssl.wrap_socket(client_proxy, ssl_version=ssl.PROTOCOL_TLSv1,
	                                     ciphers='HIGH:-aNULL:-eNULL:-PSK:RC4-SHA:RC4-MD5')

		wrapped_client_proxy.connect((server, port))

		wrapped_client_proxy.recv(8192)
		hello = "HELO ajbkh\n"
		hello = hello.encode()
		wrapped_client_proxy.send(hello)
		wrapped_client_proxy.recv(8192)

		user_pass_file = open(self.admin_user_pass_filename)
		user_pass = user_pass_file.read().split("\n")
		user_pass_file.close()
		user = user_pass[0]
		password = user_pass[1]

		user = user.encode()
		user_base64 = base64.b64encode(user)

		password = password.encode()
		password = base64.b64encode(password)

		auth_login = ('AUTH LOGIN\n').encode()
		wrapped_client_proxy.send(auth_login)
		wrapped_client_proxy.recv(8192)

		user_base64 = user_base64.decode('utf-8', 'ignore').strip("\n")
		user_base64 += "\n"
		wrapped_client_proxy.send(user_base64.encode())
		wrapped_client_proxy.recv(8192)


		password = password.decode('utf-8', 'ignore').strip("\n")
		password += "\n"
		wrapped_client_proxy.send(password.encode())
		wrapped_client_proxy.recv(8192)

		user = user.decode('utf-8', 'ignore').strip("\n")
		mail_from = 'MAIL FROM: <' + user + '>\r\n'
		mail_from = mail_from.encode()
		wrapped_client_proxy.send(mail_from)
		wrapped_client_proxy.recv(8192)


		receiver = 'eileen.jamali@gmail.com'
		to_command = 'RCPT TO: <' + receiver + '>\r\n'
		wrapped_client_proxy.send(to_command.encode())
		wrapped_client_proxy.recv(8192)

		data_command = 'DATA\r\n'
		wrapped_client_proxy.send(data_command.encode())
		wrapped_client_proxy.recv(8192)
		subject = 'Restriction Email'
		body = 'restricted HTTP request content: \n' + self.mail_content
		wrapped_client_proxy.send(("Subject: " + subject + "\r\n\r\n" + body + "\r\n\r\n.\r\n" + "\r\n").encode())
		wrapped_client_proxy.recv(8192)

		wrapped_client_proxy.send("QUIT\r\n".encode())
		wrapped_client_proxy.recv(8192)
		wrapped_client_proxy.close()


class parser:

	def __init__(self, main_data):
		self.data = main_data
		self.path = ""

	def change_time_format(self, time):
		splited_time = time.split(" ")
		year = splited_time[3]
		switcher = {
			"Jan": "01",
			"Feb": "02",
			"Mar": "03",
			"Apr": "04",
			"May": "05",
			"Jun": "06",
			"Jul": "07",
			"Aug": "08",
			"Sep": "09",
			"Oct": "10",
			"Nov": "11",
			"Dec": "12"
		}
		month = switcher.get(splited_time[2])
		day = splited_time[1]
		hms = splited_time[4]

		return year + "-" + month + "-" + day + " " + hms

	def modified_since_time_format(self, time):
		weekday = time.strftime("%a")
		ymd, hms_ms = str(time).split(" ")
		year, month, day = ymd.split("-")
		hms, ms = hms_ms.split(".")
		switcher = {
			 "01": "Jan",
			 "02": "Feb",
			 "03": "Mar",
			 "04": "Apr",
			 "05": "May",
			 "06": "Jun",
			 "07": "Jul",
			 "08": "Aug",
			 "09": "Sep",
			 "10": "Oct",
			 "11": "Nov",
			 "12": "Dec"
		}
		new_month = switcher.get(month)
		return weekday + ", " + day + " " + new_month + " " + year + " " + hms + " GMT"
	
	def http_request_maker(self, user_agent, modified_date):

		#split request
		lines = self.data.split("\r\n")
		request_line = lines[0].split(" ")
		request_line[2] = "HTTP/1.0"
		third_slash = find_nth(request_line[1], "/", 2)
		request_line[1] = request_line[1][third_slash:]
		self.path = request_line[1]
		new_req_line = request_line[0] + " " + request_line[1] + " " + request_line[2]+ "\r\n"

		#assemble msg
		request_msg = new_req_line
		is_body = False
		for i in range(1, len(lines)):
			if is_body == True:
				request_msg += lines[i]
				continue
			if lines[i] == "":
				is_body = True
				if not modified_date == None:
					request_msg += "If-Modified-Since: " + modified_date + "\r\n"
				request_msg += "\r\n"
				continue

			header_parts = lines[i].split(":")

			if header_parts[0] == "Host":
				self.host_name = header_parts[1][1:]
				self.host_ip = socket.gethostbyname(self.host_name)#deleting space at begining
				request_msg += header_parts[0] + ":" + header_parts[1] + "\r\n"

			elif header_parts[0] == "Proxy-Connection":
				request_msg += header_parts[0] + ": close" + "\r\n"
				# continue
			elif header_parts[0] == "User-Agent":
				if not user_agent == None:
					request_msg += header_parts[0] + ": " + user_agent + "\r\n"
				else:
					request_msg += header_parts[0] + ":" + header_parts[1] + "\r\n"
			elif header_parts[0] == "Accept-Encoding":
				request_msg += header_parts[0] + ": identity\r\n"

			else:
				request_msg += header_parts[0] + ":" + header_parts[1] + "\r\n"


		return request_msg

	def client_proxy_cache(self, user_agent):
		if cache_size == None: # proxy can't cache
			return 3, self.http_request_maker(user_agent, None), None
		else: # proxy can cache
			lines = self.data.split("\r\n")
			request_line = lines[0].split(" ")
			method_url = request_line[0] + " " + request_line[1]
			flg, req, meth_url = None, None, None
			cache_rw_lock.w_acquire()
			if cache.get(method_url) == None: # not in cache
				flg, req, meth_url = 1, self.http_request_maker(user_agent, None), method_url
			else: # in cache
			#lock
				cache[method_url] = (datetime.datetime.now(), cache[method_url][1], cache[method_url][2], cache[method_url][3])
				# (use time, cache time, expire time, resp+header)

				if not cache[method_url][2] == None: # has expire
					if self.change_time_format(cache[method_url][2]) <= str(datetime.datetime.now()): # expired
						flg, req, meth_url = 2, self.http_request_maker(user_agent, self.modified_since_time_format(cache[method_url][1])), method_url
					else:
						flg, req, meth_url = 0, method_url, method_url
				else: # no expire in cache
					flg, req, meth_url = 2, self.http_request_maker(user_agent, self.modified_since_time_format(cache[method_url][1])), method_url
			cache_rw_lock.w_release()
			return flg, req, meth_url, self.path

def extract_header(header_type, response):
	lines = response.split("\r\n")
	for i in range(1, len(lines)):
		if lines[i] == "":
			break
		header, content = lines[i].split(": ")
		if header == header_type:
			return content
	return None

def get_header(packet):
	lines = packet.split("\r\n")
	header = ""
	for i in range(len(lines)):
		if lines[i] == "":
			break
		header += lines[i] + "\r\n"
	return header

def get_path(req):
	lines = req.split("\r\n")
	method, path, ver = lines[0].split(" ")
	third_slash = find_nth(path, "/", 2)
	path = path[third_slash:]
	return path


def server_req_resp(message, host_ip, host_name, client_port):

	try:
		proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	except socket.error as err:
		print ("Proxy Server Socket creation failed with error %s" %(err))
	try:
		proxy_server.connect((host_ip, 80))
		write_log("Proxy opening connection to server " + host_name + "[" + host_ip + "]" + " ... Connection opened.")
	except socket.error as err:
		print ("Proxy Server Socket connection failed with error %s" %(err))
	
	try:
		proxy_server.send(message)
		write_log("Proxy sent request to server with headers:\n" + get_header(message))
	except socket.error as err:
		print ("sending message failed %s" %(err))

	msg = b''
	while True:
		token = proxy_server.recv(8192)
		if not token:
			break
		else:
			msg += token
	write_log("Server sent response to proxy with headers:\n" + get_header(msg))
	proxy_server.close()
	return msg


def get_expire(response):
	lines = response.split("\r\n")
	for i in range(1, len(lines)):
		if lines[i] == "":
			break
		else:
			header, content = lines[i].split(": ")
			if header == "Expires":
				return content
	return None

def cache_packet(response, method_url):
	lines = response.split("\r\n")
	must_cache = True
	if method_url.split(" ")[0] == "GET":
		for i in range(1, len(lines)):
			if lines[i] == "":
				break
			else:
				header, content = lines[i].split(": ")
				if header == "Pragma": # header == "Cache-Control" or
					if content == "no-cache":
						must_cache = False
		cache_rw_lock.w_acquire()
		if must_cache == True:
			if not cache.get(method_url) == None: # update cache
				cache[method_url] = (cache[method_url][0], datetime.datetime.now(), get_expire(response), response)
			else: # add in cache
				if len(cache) < cache_size:
					cache[method_url] = (datetime.datetime.now(), datetime.datetime.now(), get_expire(response), response)
				else: # LRU
					del cache[min(cache, key = cache.get())]
					cache[method_url] = (datetime.datetime.now(), datetime.datetime.now(), get_expire(response), response)
		else:
			if not cache.get(method_url) == None:
				del cache[method_url]
		cache_rw_lock.w_release()

def modified_status_code(response):
	lines = response.split("\r\n")
	response_line = lines[0].split(" ")
	return response_line[1]


def inject_navbar(response):
	response = response.decode('utf-8', 'replace')
	if not injection_body == None: 
		lines = response.split("\r\n")
		is_body = False
		new_response = ""
		body = ""
		for i in range(0, len(lines)):
			if is_body == True:
				body += lines[i] + "\r\n"
			elif lines[i] == "":
				is_body = True
				new_response += "\r\n"
			else:
				new_response += lines[i] + "\r\n"
		body_tag_index = find_nth(body, "<body>", 0)
		added_body = "<div style = \"background-color: #154000; color: white\">" + injection_body + "\n</div>\n"
		new_response += body[:body_tag_index + 5] + added_body + body[body_tag_index + 6:]

	new_response = new_response.encode('utf-8')
	return new_response


def inject(response, path):
	content_type = extract_header("Content-Type", response)
	if path == "/" and find_nth(content_type, "text/html", 0) != -1:
		content_encoding = extract_header("Content-Encoding", response)
		response = inject_navbar(response)
	return response


def proxy_client_data_maker(cache_flag, request_msg, parse, client_port, method_url, path):
	if cache_flag == 3: # can't cache
		response = server_req_resp(request_msg, parse.host_ip, parse.host_name, client_port)
		response = inject(response, path)
	elif cache_flag == 0: # in cache and not expired
		write_log("cache hit with request: " + method_url + " " + path)
		cache_rw_lock.r_acquire()
		response = cache[method_url][3]
		cache_rw_lock.r_release()
	elif cache_flag == 1: # not in cache
		write_log("cache miss with request: " + method_url + " " + path)
		response = server_req_resp(request_msg, parse.host_ip, parse.host_name, client_port)
		response = inject(response, path)
		cache_packet(response, method_url)
	else:
		write_log("cache hit with request: " + method_url + " " + path)
		response = server_req_resp(request_msg, parse.host_ip, parse.host_name, client_port)
		if modified_status_code(response) == "304":
			cache_rw_lock.r_acquire()
			write_log("request " + method_url + " " + path + "is not modified since cached [" + str(cache[method_url][1]) + "]")
			response = cache[method_url][3]
			cache_rw_lock.r_release()
		elif modified_status_code(response) == "200":
			write_log("request " + method_url + " " + path + "was modified")
			response = inject(response, path)
			cache_packet(response, method_url)
		else:
			print ("error in response of server in proxy client data maker")
			response = inject(response, path)
	return response

def check_restriction_and_notify(main_data):
	host_name = extract_header("Host", main_data)
	for dic in restrictions:
		if dic["URL"] == host_name or dic["URL"] == host_name[4:]:
			if dic["notify"] == True and get_path(main_data) == "/":
				mail = mail_telnet(main_data, "admin.txt")
				mail.run()
			return True
	return False
			
def check_user_ip(client_ip):
	for dic in accountings:
		if dic["IP"] == client_ip:
			return int(dic["volume"])
	return None

def update_volume(client_ip, val):
	accounting_rw_lock.acquire()
	for dic in accountings:
		if dic["IP"] == client_ip:
			dic["volume"] = str(int(dic["volume"]) - val)
			volume = int(dic["volume"])
			accounting_rw_lock.release()
			return volume
	accounting_rw_lock.release()



def client_thread(client_data, client_port, client_ip):
	volume = check_user_ip(client_ip)
	if volume == None:
		write_log("Connection Closed")
		client_data.close()
		return

	main_data = client_data.recv(8192)
	if not main_data:
		write_log("Connection Closed")
		client_data.close()
		return
	write_log("Client sent request to proxy with headers:\n" + get_header(main_data) + "\n")

	if check_restriction_and_notify(main_data) == True:
		client_data.send("Permission Denied!")
		write_log("Connection Closed")
		client_data.close()
		return

	write_log("connect to [127.0.0.1] from [" + client_ip + "] " + str(client_port))

	parse = parser(main_data)
	cache_flag, request_msg, method_url, path = parse.client_proxy_cache(user_agent)
	write_log("\n------------------------\n" + get_header(request_msg) + "\n ------------------------\n")

	if len(request_msg) > volume: # no enough volume for sending request
		write_log("Connection Closed")
		client_data.close()
		del parse
		return

	volume = update_volume(client_ip, len(request_msg))



	proxy_client_data = proxy_client_data_maker(cache_flag, request_msg, parse, client_port, method_url, path)

	if len(proxy_client_data) > volume:
		client_data.close()
		del parse
		return
	volume = update_volume(client_ip, len(proxy_client_data))


	client_data.send(proxy_client_data)
	write_log("Proxy sent response to client with headers:\n" + get_header(proxy_client_data))
	client_data.close()
	del parse


con = config()
port = con.get_port()
user_agent = con.get_privacy()
cache_size = con.get_cache_size()
log_file = con.get_logging()
restrictions = con.get_restriction()
accountings = con.get_accounting()
injection_body = con.get_injection()

i = 0
threads = []
localhost = "127.0.0.1"

log_lock = threading.Lock()
write_log("Proxy launched")


try:
	client_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client_proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	write_log("Creating server socket...")
except socket.error as err:
	print ("Socket creation failed with error %s" %(err))
try:
	client_proxy.bind((localhost, port))
	write_log("Binding socket to port " + str(port) + "...")
except socket.error as err:
	print ("Client Proxy Socket bind failed\n")
client_proxy.listen(1000)		# at most 1000 clients can connect to this socket

while True:
	write_log("Listening for incoming requests...")
	try:
		client_data, (client_ip, client_port)  = client_proxy.accept()
		write_log("Accepted a request from client!")
	except socket.error as err:
		print ("Client Proxy Socket acception failed\n")

	thread = threading.Thread(name = i, target = client_thread, args = (client_data, client_port, client_ip, ))
	thread.start()
	threads.append(thread)
	i += 1

for i in threads:
	i.join()