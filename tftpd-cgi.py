#!/usr/bin/python

import socket, select, struct
import os, time

# config

hostname = ''
port = 69
basedir = os.getcwd()
cgidir = 'cgi'

# end config

opcode = struct.Struct('>H')
rhshort = struct.Struct('<H')
datap = errorp = ackp = struct.Struct('>HH')

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((hostname, port))

queue = {}
sockets = set([server])
socketmap = {}

# folder setup

basecgi = os.path.join(basedir, cgidir)
if not os.path.exists(basecgi):
	os.makedirs(basecgi)

class Op:
	READ = 1
	WRITE = 2
	DATA = 3
	ACK = 4
	ERROR = 5

	tostr = {
		READ: 'READ',
		WRITE: 'WRITE',
		DATA: 'DATA',
		ACK: 'ACK',
		ERROR: 'ERROR'
	}

	@classmethod
	def str(cls, op):
		if op in cls.tostr:
			return cls.tostr[op]
		else:
			raise IndexError

class Request:
	def __init__(self, ip, port, op, filename, mode):
		self.ip = ip
		self.port = port
		self.op = op
		self.filename = filename
		self.mode = mode
		self.block = 1
		self.ackn = 0
		self.ackt = 0
		self.nack = {}
	
	def send(self, packet):
		self.sock.sendto(packet, (self.ip, self.port))
	
	def recv(self, packet):
		self.sock.recvfrom(1024)

	def create(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind((hostname, 0))
		self.lport = s.getsockname()[1]

		if self.op == Op.WRITE:
			self.nack[0] = ackp.pack(Op.WRITE, 0)
		else:
			self.ackt = time.time()

		self.sock = s
		return s
	
	def serve(self):
		if self.op == Op.READ:
			self.read()
		elif self.op == Op.WRITE:
			self.write()
	
	def finish(self):
		raise socket.error
	
	def poll(self):
		packet = self.recv()
		if self.op == Op.READ:
			if len(packet) != 4:
				raise socket.error
			
			opcode, ackn = ackp.unpack(packet)
			if opcode != Op.ACK:
				raise socket.error
			
			self.ackn = max(ackn, self.ackn)
		elif self.op == Op.WRITE:
			print packet
	
	def ack(self, re=False, timer=3):
		if self.nack:
			now = time.time()
			if not re or self.ackt < now - timer:
				self.ackt = now
				for packet in self.nack.values():
					self.send(packet)
		elif self.finished:
			self.finish()
	
	def chunk(self, data, op=Op.DATA):
		for i in xrange(0, len(data), 512):
			packet = datap.pack(op, self.block) + data[i:i+512]
			self.nack[self.block] = packet
			self.block += 1
		
			if i + 512 == len(data):
				self.nack[self.block] = datap.pack(op, self.block)
				self.block += 1
				self.finished = True
				break
			elif i + 512 > len(data):
				self.finished = True
				break
		else:
			self.nack[self.block] = datap.pack(op, self.block)
			self.block += 1
			self.finished = True

	def read(self):
		path = os.path.join(basedir, self.filename)
		data = False
		if os.path.exists(path):
			if self.filename.startswith(cgidir + os.sep):
				print 'running', path
				os.environ['REMOTE_HOST'] = self.ip
				os.environ['REMOTE_PORT'] = str(self.port)
				data = os.popen(path).read()
			else:
				print 'reading', path
				f = open(path, 'r')
				data = f.read()
				f.close()
		
		if data is False:
			print 'could not read', path
			packet = opcode.pack(Op.ERROR) + rhshort.pack(3) + 'could not read '+self.filename+'\0'
			self.nack[self.block] = packet
		else:
			self.chunk(data)

		self.ack()
	
	def write(self, data):
		pass

def pump():
	while True:
		i, _, _ = select.select([server], [], [])

		for s in i:
			if s == server:
				data, addr = s.recvfrom(1024)
				ip, port = addr
				data = buffer(data)
				op, = opcode.unpack(data[:2])

				if op in (Op.READ, Op.WRITE):
					filename, mode = data[2:].split('\0')[:2]

					if addr in queue:
						if filename in queue[ip]:
							continue
						else:
							queue[ip].add(filename)
					else:
						queue[ip] = set((filename,))
					
					print '%s /%s from %s:%s' % (Op.str(op), filename, ip, port),
					print '(mode: "%s")' % (mode)

					req = Request(ip, port, op, filename, mode)
					sock = req.create()
					req.serve()
					socketmap[sock] = req
			elif s in socketmap:
				try:
					socketmap[s].poll()
				except socket.error:
					try:
						s.shutdown()
						s.close()
					except:
						pass
					finally:
						del socketmap[s]
						sockets.remove(s)
						queue[req.ip].remove(req.filename)
			else:
				sockets.remove(s)
		
		for s in sockets:
			if not s == server and not s in i:
				if s in socketmap:
					socketmap[s].ack(True)
				else:
					sockets.remove(s)

if __name__ == '__main__':
	pump()