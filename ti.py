#!/usr/bin/env python
# -*- coding: utf-8 -*-

#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
#  Copyrigth (C) 1014 Sampsa Vierros
#  All rights reserved.

import serial
import struct
from time import sleep, time
from string import strip

def readVariablesFromFile(filePath, verbose=True):
	fp = open(filePath, 'r')
	signature = fp.read(8)
	magic = fp.read(3)
	comment = fp.read(42)
	length = ord(fp.read(1)) | (ord(fp.read(1)) << 8)
	if verbose:
		print signature
		print "Comment: %s" % comment
		print "Length: %i" % length
	variables = []
	bytes = 0
	while bytes < length:
		dummy = ord(fp.read(1)) | (ord(fp.read(1)) << 8)
		size = ord(fp.read(1)) | (ord(fp.read(1)) << 8)
		varType = ord(fp.read(1))
		nameSize = ord(fp.read(1))
		name = fp.read(8)
		varSize = ord(fp.read(1)) | (ord(fp.read(1)) << 8)
		data = fp.read(varSize)
		if verbose:
			print "Variable name: %s %i bytes" % (name, varSize)
		bytes += 16 + varSize
		variables.append((varSize, varType, nameSize, name[0:nameSize], data))	
	checksum = ord(fp.read(1)) | (ord(fp.read(1)) << 8)
	if verbose:
		print "Checksum: %i" % checksum
	fp.close()
	files = []
	for var in variables:
		files.append(Ti86Variable(name=var[3], type=var[1], data=var[4]))
	return files		

class Ti86Variable:	
	''' This represents the variable formats '''
	
	types = {
		0x00 : ['REAL', '.86n'],
		0x01 : ['COMPLEX', '.86c'],
		0x02 : ['VECTOR', '.86v'],
		0x03 : ['VECTOR', '.86v'],
		0x04 : ['LIST', '.86l'],
		0x05 : ['LIST', '.86l'],
		0x06 : ['MATRIX', '.86m'],
		0x07 : ['MATRIX', '.86m'],
		0x08 : ['CONSTANT', '.86k'],
		0x09 : ['CONSTANT', '.86k'],
		0x0A : ['EQUATION', '.86e'],
		0x0C : ['STRING', '.86s'],
		0x0D : ['FUNCTION', '.86d'],
		0x0E : ['POLAR', '.86d'],
		0x0F : ['PARAMETRIC', '.86d'],
		0x10 : ['DIFFEQ', '.86d'],
		0x11 : ['PICTURE', '.86i'],
		0x12 : ['PROGRAM', '.86p'],
		0x15 : ['DIR', ''],
		0x17 : ['FUNCWINDOW', '.86w'],
		0x18 : ['POLARWINDOW','.86w'],
		0x19 : ['PARAMWINDOW','.86w'],
		0x1A : ['DIFFEQWINDOW', '.86w'],
		0x1B : ['WINDOW', '.86w'],
		0x1D : ['BACKUP', ''],
		0x1E : ['UNKNOWN', ''],
		0x2A : ['EQUATION', '']
		}
	
	def __init__(self, *args, **kwargs):
		self.name = ''
		self.type = 0
		self.data = 0
		if len(kwargs) != 0:
			for key in kwargs:
				if key == 'name':
					self.name = kwargs[key]
				elif key == 'type':
					self.type = kwargs[key]
				elif key == 'data':
					self.data = kwargs[key]
				elif key == 'raw':
					pass
		elif len(args) == 3:
			self.name = args[0]
			self.type = args[1]
			self.data = args[2]
	
	def getName(self):
		return self.name

	def getFullName(self):
		return self.name + self.types[self.type][1]

	def getSize(self):
		return len(self.data)

	def getData(self):
		return self.data

	def __getslice__(self, start, end):
		return self.data[start:end]
	
	def getChecksum(self):
		return Ti86Checksum(self.data)

	def getArchiveable(self):
		signature = '**TI86**'
		magic = [0x1A, 0x0A, 0x00]	# translates to 1A 0A 00 in file
		comment = 'Comment line'.ljust(42, '\0')
		dummy = '  '
		length = len(self.data)
		flength = length + 16
		
		data = ''
		data += struct.pack('<8s', signature)
		data += struct.pack('<B', 0x1A)
		data += struct.pack('<B', 0x0A)
		data += struct.pack('<B', 0x00)
		data += struct.pack('<42s', comment)
		data += struct.pack('<H', flength) # File size
		# Per variable block
		data += struct.pack('<H', 0x0000) # Dummy
		data += struct.pack('<H', length)
		data += struct.pack('<B', self.type) # Variable type
		data += struct.pack('<B', len(self.name)) # Name length
		data += struct.pack('<8s', self.name.ljust(8, '\0')) # Name
		data += struct.pack('<H', length)
		data += struct.pack('<%is' % len(self.data), str(self.data))
		data += struct.pack('<H', Ti86Checksum(data))
		return data
		
	def getHeader(self):
		return Ti86Header(self.name, self.type, len(self.data), True)

	def getData(self):
		return self.data	

def Ti86Checksum(data):
	checksum = 0
	for idx in xrange(len(data)):
		checksum += ord(data[idx])
	return checksum & 0xFFFF

class Ti86Header:
	''' Variable header '''
	def __init__(self, *args, **kwargs):
		# Ti86Header(name, type, length, isPadded=False)
		# Ti86Header(raw=<bytes>)
		self.isPadded = False
		if len(kwargs) != 0:
			for key in kwargs:
				if key == 'raw':
					buf = kwargs[key]
					self.length =  ord(buf[0]) | (ord(buf[1]) << 8)
					self.type = ord(buf[2])
					count = ord(buf[3])
					self.name = buf[4:4+count] # Fix checksum
		elif len(args) == 3:
			self.type = args[1]
			self.length = args[2]
			self.name = args[0]
		elif len(args) == 4:
			self.type = args[1]
			self.length = args[2]
			self.isPadded = True
			self.name = args[0]
			self.isPadded = args[3]
		else:
			raise Exception
	
	def __str__(self):
		padded = self.name
		if self.isPadded == True:
			padded = padded.ljust(8, '\x20')
		return struct.pack('<HBB%is' % len(padded), self.length, self.type, len(self.name), padded)

class Ti86Packet:
	def __init__(self, **kwargs):
		self.sender = 0
		self.cmd = 0
		self.length = 0
		self.data = None
		self.checksum = None
		for key in kwargs:
			if key == 'sender':
				self.sender = kwargs[key]
			elif key == 'cmd':
				self.cmd = kwargs[key]
			elif key == 'length':
				self.length = kwargs[key]
			elif key == 'data':
				self.data = kwargs[key]
			elif key == 'checksum':
				self.checksum = kwargs[key]
			elif key == 'raw':
				buf = kwargs[key]
				self.sender = ord(buf[0])
				self.cmd = ord(buf[1])
				self.length = ord(buf[2]) | (ord(buf[3]) << 8)
				if len(buf) > 4:
					self.data = buf[4:-2]
					self.checksum = ord(buf[-2]) | (ord(buf[-1]) << 8)
	def __str__(self):
		if self.data != None:
			return struct.pack('<BBH%isH' % len(self.data), 
				self.sender, self.cmd, self.length, self.data, self.checksum)
		else:
			return struct.pack('<BBH', self.sender, self.cmd, self.length)
	def __len__(self):
		if self.data != None:
			return len(self.data)
		else:
			return 0
	def __getitem__(self, idx):
		data = self.__str__()
		return data[idx]
	
	def isGood(self):
		if self.checksum == None:
			return True
		elif self.checksum == Ti86Checksum(self.data):
			return True
		else:
			return False
	def show(self):
		line = ''
		data = self.__str__()
		for idx in xrange(len(data)):
			line += hex(ord(data[idx]))[2:].rjust(2, '0')
			line += ' '
		return line

# Packet shortcuts
class Ti86Acknowledge(Ti86Packet):
	def __init__(self, sender, nbytes=0):
		Ti86Packet.__init__(self, sender=sender, cmd=0x56, length=nbytes)

class Ti86ClearToSend(Ti86Packet):
	def __init__(self, sender, nbytes=0):
		Ti86Packet.__init__(self, sender=sender, cmd=0x09)

class Ti86Reject(Ti86Packet):
	def __init__(self, sender, code):
		Ti86Packet.__init__(self, sender=sender, cmd=0x36, length=1, data=code, checksum=code)

class Ti86ChecksumError(Ti86Packet):
	def __init__(self, sender):
		Ti86Packet.__init__(self, sender=sender, cmd=0x5A)

class Ti86RequestVariable(Ti86Packet):
	def __init__(self, sender, header):
		data = str(header)
		Ti86Packet.__init__(self, sender=sender, cmd=0xA2, length=len(data), data=data, checksum=Ti86Checksum(data))

class Ti86RequestDirectory(Ti86Packet):
	def __init__(self, sender):
		data = '\x00\x00\x15\x00\x00'
		Ti86Packet.__init__(self, sender=sender, cmd=0xA2, length=len(data), data=data, checksum=Ti86Checksum(data))

class Ti86Screenshot(Ti86Packet):
	def __init__(self, sender):
		Ti86Packet.__init__(self, sender=sender, cmd=0x6D)

class Ti86EndTransmission(Ti86Packet):
	def __init__(self, sender):
		Ti86Packet.__init__(self, sender=sender, cmd=0x92)

class Ti86DirectCommand(Ti86Packet):
	def __init__(self, sender, command):
		Ti86Packet.__init__(self, sender=sender, cmd=0x87, length=command)

class Ti86RequestToSend(Ti86Packet):
	def __init__(self, sender, header):
		padded = Ti86Header(header.name, header.type, header.length, True)
		data = str(padded)
		Ti86Packet.__init__(self, sender=sender, cmd=0xC9, length=len(data), data=data, checksum=Ti86Checksum(data))

class Ti86DataPacket(Ti86Packet):
	def __init__(self, sender, data):
		Ti86Packet.__init__(self, sender=sender, cmd=0x15, length=len(data), data=data, checksum=Ti86Checksum(data))

# Errors
class Ti86DriverError(Exception):
	''' Used to wrap driver implementation specific errors. 
		Not visible outside Driver class. '''
	def __init__(self, msg):
		self.msg = msg
	def __str__(self):
		return repr(self.msg)

class Ti86TimeoutError(Exception):
	''' Driver raises timeout errors when no data was received. '''
	def __init__(self, msg):
		self.msg = msg
	def __std__(self):
		return repr(self.msg)

class Ti86ProtocolError(Exception):
	''' This error signals that packet was received out of sequence or not at all. '''
	def __init__(self, msg):
		self.msg = msg
	def __std__(self):
		return repr(self.msg)

class Ti86RejectionError(Exception):
	''' This error signals that exchange went according to protocol, but terminated
		without the desired outcome i.e. exchange canceled by the calculator. '''
	def __init__(self, msg):
		self.msg = msg
	def __std__(self):
		return repr(self.msg)

class Ti86Exchange:
	def __init__(self, driver):
		self.sender = 0x06
		self.driver = driver
		self.packets = []
	
	def request(self, packet):
		''' Sends a request maximum of 'repeats' times. Returns the
			reply packet. '''
		good = False
		repeats = 3
		reply = None
		for i in xrange(repeats):
			self.driver.send(packet)
			self.packets.append(('OUT', packet.show()))
			try:
				reply = self.driver.receive()
			except Ti86TimeoutError as error:
				print error.msg
				continue
			good = True
			break
		if good != True:
			raise Ti86ProtocolError('Did not receive reply to request.')
		return reply
	
	def receive(self):
		''' Tries to receive a packet. Corrupted packets are automatically
			re-requested. '''
		success = False
		repeats = 3
		reply = None
		for i in xrange(repeats):
			try:
				reply = self.driver.receive()
				self.packets.append(('IN', reply.show()))
			except Ti86TimeoutError as error:
				print error.msg
				continue
			if reply.isGood() != True:
				self.driver.send(Ti86ChecksumError(self.sender))
				self.packets.append(('OUT', Ti86ChecksumError(self.sender).show()))
				continue
			success = True
			break
		if success != True:
			raise Ti86ProtocolError('Did not receive packet.')
		self.driver.send(Ti86Acknowledge(self.sender))
		self.packets.append(('OUT', Ti86Acknowledge(self.sender).show()))
		return reply
	
	def send(self, packet):
		''' Sends a packet maximum of 'repeats' times depending on the
			reply packet. Automatically resends corrupt packets. '''
		success = False
		repeats = 3
		reply = None
		for i in xrange(repeats):
			self.driver.send(packet)
			self.packets.append(('OUT', packet.show()))
			try:
				reply = self.driver.receive()
				self.packets.append(('IN', reply.show()))
			except Ti86TimeoutError:
				continue
			if reply.cmd == 0x5A: # Checksum error
				continue
			success = True
			break
		if success != True:
			raise Ti86ProtocolError('Did not receive reply to sent packet.')
		return reply

# Silent link protocols
class Ti86ScreenshotExchange(Ti86Exchange):
	def __init__(self, driver):
		Ti86Exchange.__init__(self, driver)
	
	def execute(self):
		self.request(Ti86Screenshot(self.sender))
		data = self.receive()
		return data.data

class Ti86DirectoryListingExchange(Ti86Exchange):
	def __init__(self, driver):
		Ti86Exchange.__init__(self, driver)
	
	def execute(self):
		reply = self.request(Ti86RequestDirectory(self.sender))
		freemem = self.receive()
		info = []
		eot = False
		while eot != True:
			packet = self.receive()
			if packet.cmd == 0x92: # EOT
				eot = True
			elif packet.cmd == 0x06: # VAR
				header = Ti86Header(raw=packet.data)
				info.append((header.length, header.name, header.type))
			else:
				pass
		return info

class Ti86VariableDownloadExchange(Ti86Exchange):
	def __init__(self, driver, name):
		Ti86Exchange.__init__(self, driver)
		self.name = name
	
	def execute(self):
		reply = self.request(Ti86RequestVariable(self.sender, Ti86Header(self.name, 0x1E, 0x0)))
		header = self.receive()
		# Check if requested variable exists
		if header.cmd == 0x36: # Reject packet
			raise Ti86RejectionError('No variable by the name %s' % self.name)
		self.request(Ti86ClearToSend(self.sender))
		packet = self.receive()
		return Ti86Header(raw=header.data), packet.data

class Ti86VariableUploadExchange(Ti86Exchange):
	def __init__(self, driver, header, data):
		Ti86Exchange.__init__(self, driver)
		self.header = header
		self.data = data
	
	def execute(self):
		self.request(Ti86RequestToSend(self.sender, self.header))
		packet = self.receive()
		if packet.cmd == 0x36: # Reject packet
			raise Ti86RejectionError('Device is out of memory')
		self.send(Ti86DataPacket(self.sender, self.data))
		self.driver.send(Ti86EndTransmission(self.sender))
		return None

class Ti86Driver:
	''' Driver class provides the low-level communications between the PC and the
		link hardware. Subclass and implement read and write for alternative hardware. 
	'''
	def __init__(self):
		pass

	def send(self, packet):
		self.write(packet)
	
	def receive(self):
		# Tries to receive a packet. On timeout raises TimeoutError.
		valid = False
		sender = cmd = length = 0
		#self.flush()
		bytes = self.read(4)
		if len(bytes) == 4:
			sender = ord(bytes[0])
			cmd = ord(bytes[1])
			length = ord(bytes[2]) | (ord(bytes[3]) << 8)
			valid = True
		else:
			raise Ti86TimeoutError('Receive timed out with buffer: %s' % bytes)
		if length == 0:
			return Ti86Packet(sender=sender, cmd=cmd, length=length)
		elif cmd in [0x56, 0x36, 0x92, 0x09]:
			# Cases where length has special meaning.
			return Ti86Packet(sender=sender, cmd=cmd, length=length)		
		else:		
			# Packet has data payload
			count = 0	# Number of bytes read
			recoveries = 10
			data = ''
			while count != length:
				remaining = length - count
				increment = min(32, remaining)
				try:
					# Try reading a chunck of data
					data += self.read(increment)
					count += increment
				except Ti86DriverError:
					# Wait and try again
					sleep(3)
					recoveries -= 1
					if recoveries == 0:
						break
			if recoveries == 0:
				# Device is non-responsive (has shutdown etc.), return
				# to prevent complete hang
				raise Ti86TimeoutError('Got partial package until timed out.')
			bytes = self.read(2)	# Get checksum
			if len(bytes) == 2:
				checksum = ord(bytes[0]) | (ord(bytes[1]) << 8)
				return Ti86Packet(sender=sender, cmd=cmd, length=length, data=data, checksum=checksum)
			else:
				# Silently add checksum if failed to get
				raise Ti86TimeoutError('Could not read checksum.')
				return Ti86Packet(sender=sender, cmd=cmd, length=length, data=data, checksum=0xFFFF)
	
	def read(self, nbytes):
		raise NotImplementedError
	
	def write(self, bytes):
		raise NotImplementedError
	
	def flush(self):
		raise NotImplementedError


class ArduinoSerialDriver(Ti86Driver):
	def __init__(self, port, baudrate, burstsize = 32, burstdelay = 1.0):
		Ti86Driver.__init__(self)
		self.port = port
		self.rate = baudrate
		self.burstsize = burstsize
		self.burstdelay = burstdelay
		
		try:
			self.com = serial.Serial(self.port, self.rate, timeout=1)
			self.com.open()
			self.com.flushInput()
			self.com.flushOutput()
		except serial.serialutil.SerialException:
			raise Ti86DriverError('Failed to open serial port.')
		
		print "Resetting link..."
		sleep(3) # Wait for the link to reset
		print "Done."

	def write(self, bytes):
		# Fill buffer in small chunks. Too large bursts will overwhelm the
		# receive buffer in the link device as will too rapid bursts.
		bufsize = self.burstsize
		nbytes = 0
		raw = str(bytes)
		while nbytes < len(raw):
			if nbytes+bufsize >= len(raw):
				self.com.write(raw[nbytes:])
			else:
				self.com.write(raw[nbytes:nbytes+bufsize])
			nbytes += bufsize
			# Allow link hardware time to empty the input buffer.
			sleep(self.burstdelay)
	
	def read(self, nbytes):
		try:
			return self.com.read(nbytes)
		except serial.serialutil.SerialException:
			raise Ti86DriverError('Failed to read from serial port.')
	
	def flush(self):
		self.com.flushInput()

# Note: Requires pyusb-1.0 to work (not 0.x)
import usb
from usb.util import *
import time

class USBDriver(Ti86Driver):
	RQ_STATUS      = 0
	RQ_DATA_WRITE  = 1
	RQ_DATA_READ   = 2
	RQ_GET_INFO    = 3
	RQ_SET_DELAY   = 4

	STATUS_IDLE    = 0	# Device can accept new commands
	STATUS_WRITING = 1	# Device is still writing previous burst
	STATUS_WAITING = 2
	STATUS_READING = 3	# Device is reading a byte
	STATUS_PENDING = 4  # Device has data from the calculator ready to be read
	
	def __init__(self):
		Ti86Driver.__init__(self)
		self.dev = usb.core.find(idVendor=0x6666, idProduct=0x0000)
		if self.dev is None:
			raise Ti86DriverError('USB device not found.')
		self.rqStatus = CTRL_TYPE_VENDOR | CTRL_RECIPIENT_DEVICE | ENDPOINT_IN
		self.rqRead = self.rqStatus
		self.rqInfo = self.rqStatus
		self.rqDelay = CTRL_TYPE_VENDOR | CTRL_RECIPIENT_DEVICE
		self.rqWrite = CTRL_TYPE_VENDOR | CTRL_RECIPIENT_DEVICE | ENDPOINT_OUT
		self.burstdelay = 0.25
		self.timeout = 1.0
		self.burstsize = self.getBufferSize()
		self.read_buffer = ''
		self.setDelay(10)	# Default, transfer speed about 1kbit/s, lower delay values are unstable
			
	def getBufferSize(self):
		ret = self.dev.ctrl_transfer( \
			bmRequestType=self.rqInfo, \
			bRequest=self.RQ_GET_INFO, \
			wValue=0x0, \
			wIndex=0x0, \
			data_or_wLength=1, \
			timeout = 500)
		if len(ret) != 1:
			return -1
		length = ret[0]
		return length
	
	def setDelay(self, delay):
		self.dev.ctrl_transfer( \
			bmRequestType=self.rqDelay, \
			bRequest=self.RQ_SET_DELAY, \
			wValue=0x0, \
			wIndex=delay, \
			data_or_wLength=0, \
			timeout=500)
	
	def pollStatus(self):
		ret = self.dev.ctrl_transfer( \
			bmRequestType=self.rqStatus, \
			bRequest=self.RQ_STATUS, \
			wValue=0x0, \
			wIndex=0x0, \
			data_or_wLength=1, \
			timeout = 500)
		if len(ret) != 1:
			return -1
		status = ret[0]
		return status
	
	def waitWrite(self):
		# Wait until device goes back to idle after emptying its write buffer.
		status = self.pollStatus()
		if status == self.STATUS_IDLE:
			return True
		startTime = time.clock()
		while ((time.clock() - startTime) < self.timeout):
			status = self.pollStatus()
			if status == self.STATUS_IDLE:
				return True
		return False
	
	def waitRead(self):
		# Wait until device has something to send to the host.
		status = self.pollStatus()
		if status == self.STATUS_PENDING:
			return True
		startTime = time.clock()
		while ((time.clock() - startTime) < self.timeout):
			status = self.pollStatus()
			if status == self.STATUS_PENDING:
				return True
		return False
	
	def read(self, nbytes):
		startTime = time.clock()
		while len(self.read_buffer) < nbytes:
			self.waitRead()
			raw = self.read_raw()
			if len(raw) > 0:
				self.read_buffer += raw
			if (time.clock() - startTime) > self.timeout:
				raise Ti86DriverError('Read timed out.')
		data = self.read_buffer[:nbytes]
		self.read_buffer = self.read_buffer[nbytes:]
		return data
	
	def read_raw(self):
		data = self.dev.ctrl_transfer( \
			bmRequestType=self.rqRead, \
			bRequest=self.RQ_DATA_READ, \
			wValue=0x0, \
			wIndex=0x0, \
			data_or_wLength=self.burstsize, \
			timeout = 500)
		bytes = ''.join([chr(byte) for byte in data])
		return bytes
	
	def write(self, bytes):
		bufsize = self.burstsize
		nbytes = 0
		raw = str(bytes)
		while nbytes < len(raw):
			if self.waitWrite() == False:
				raise Ti86DriverError('Write timed out.')
			if nbytes+bufsize >= len(raw):
				data = raw[nbytes:]
				self.dev.ctrl_transfer( \
					bmRequestType=self.rqWrite, \
					bRequest=self.RQ_DATA_WRITE, \
					wValue=0x0, \
					wIndex=0x0, \
					data_or_wLength=data, \
					timeout = 500)
			else:
				data = raw[nbytes:nbytes+bufsize]
				self.dev.ctrl_transfer( \
					bmRequestType=self.rqWrite, \
					bRequest=self.RQ_DATA_WRITE, \
					wValue=0x0, \
					wIndex=0x0, \
					data_or_wLength=data, \
					timeout = 500)
			nbytes += bufsize
			#time.sleep(self.burstdelay)
	
	def flush(self):
		if self.waitWrite() == False:
			raise Ti86DriverError('No reply')


class Logger:
	def __init__(self, filePath):
		self.fp = open(filePath, 'a')
		self.write('###################################\n')
		self.write('Opened log session at %i\n' % time())
		self.write('###################################\n')
	def __del__(self):
		self.fp.close()
	def write(self, msg):
		self.fp.write(msg)

# Command-line utility
if __name__ == '__main__':
	import sys
	import getopt
	
	delay = 1.0
	size = 32
	bauds = 115200
	getListing = False
	getScreenshot = False
	outFile = None
	variableName = None
	variableFile = None
	portName = None
	linkName = None
	
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hlsd:B:b:o:f:n:p:c:")
	except getopt.GetoptError:
		print 'ti.py -h -l -s -d seconds -B bytes -b bauds -o out -n name -f file'
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-h"):
			print 'ti.py -h -l -s -d seconds -B bytes -b bauds -o out -n name -f file'
			print '-l         request variable listing'
			print '-s         request screenshot'
			print '-n name    request variable'
			print '-f file    upload variables from archive file'
			print '-o out     filename for downloaded variables'
			print '-B bytes   burst size'
			print '-d delay   delay between bursts in seconds'
			print '-b bauds   serial transfer speed'
			print '-p port    serial port name, for example /dev/ttyACM0'
			print '-c         driver hardware (arduino or usb)'
			print '-h         print this page'
			sys.exit(2)
		elif opt in ("-d"):
			delay = float(arg)
		elif opt in ("-B"):
			size = int(arg)
		elif opt in ("-b"):
			bauds = int(arg)
		elif opt in("-l"):
			getListing = True
		elif opt in ("-s"):
			getScreenshot = True
		elif opt in("-o"):
			outFile = arg
		elif opt in("-n"):
			variableName = arg
		elif opt in("-f"):
			variableFile = arg
		elif opt in("-p"):
			portName = arg  # /dev/ttyACM0
		elif opt in ("-c"):
			linkName = arg

	if linkName == None:
		print 'Name a driver hardware.'
		sys.exit(2)
	
	if linkName == 'arduino':
		if portName == None:
			sys.exit(2)
		try:
			driver = ArduinoSerialDriver(portName, bauds, burstsize=size, burstdelay=delay)
		except Ti86DriverError:
			print 'Failed to open port %s' % portName
			sys.exit(2)
	elif linkName == 'usb':
		try:
			driver = USBDriver()
		except Ti86DriverError:
			print 'Device not found.'
			sys.exit(2)
	
	if getListing != False:
		exchange = Ti86DirectoryListingExchange(driver)
		print 'Variables'
		print '%s' % (''.ljust(40, '='))
		try:
			lst = exchange.execute()
			for entry in lst:
				try:
					name = Ti86Variable.types[entry[2]][0].ljust(12, ' ')
				except KeyError:
					name = 'UNKNOWN (%x)' % entry[2]
					name = name.ljust(12, ' ')
				print '%s %s (%i bytes)' % (entry[1].ljust(12, ' '), name, entry[0])
		except Ti86ProtocolError:
			print 'Failed to get directory listing.'
	
	if outFile == None:
		outFile = variableName
	
	if getScreenshot:
		if outFile == None:
			outFile = 'screenshot.txt'
		exchange = Ti86ScreenshotExchange(driver)
		try:
			data = exchange.execute()		
		except Ti86ProtocolError:
			print 'Failed to download screenshot.'
			sys.exit(2)
		# Convert and save
		fp = open(outFile, 'w')
		for y in xrange(64):
			for x in xrange(16):
				idx = y * 16 + x
				for i in xrange(8):
					bit = (ord(data[idx]) << i) & 0x80
					if bit == 0:
						fp.write(' ')
					else:
						fp.write('X')
			fp.write('\n')
		fp.close()			
	
	if variableName != None:
		exchange = Ti86VariableDownloadExchange(driver, variableName)
		archiveable = None
		try:	
			variable = exchange.execute()
			archiveable = Ti86Variable(name=variable[0].name, \
				type=variable[0].type, data=variable[1]).getArchiveable()
		except Ti86ProtocolError:
			print 'Failed to download variable %s.' % variableName
		except Ti86RejectionError:
			print 'No variable with name %s.' % variableName
		if archiveable != None:
			fp = open(outFile, 'w')
			fp.write(archiveable)
			fp.close()
	
	if variableFile != None:
		variables = readVariablesFromFile(variableFile, True)
		idx = -1
		if len(variables) > 1:
			try:
				idx = int(raw_input('Select variable index or hit enter to upload all. '))
			except ValueError:
				idx = -1
		if idx != -1:
			exchange = Ti86VariableUploadExchange(driver, variables[idx].getHeader(), variables[idx].getData())
			try:
				exchange.execute()
			except Ti86ProtocolError:
				print 'Failed to upload variable %s.' % variables[idx].getName()
			except Ti86RejectionError:
					print 'Calculator out of memory.'
		else:
			for variable in variables:
				exchange = Ti86VariableUploadExchange(driver, variable.getHeader(), variable.getData())
				try:
					exchange.execute()
				except Ti86ProtocolError:
					print 'Failed to upload variable %s.' % variable.getName()
				except Ti86RejectionError:
					print 'Calculator out of memory.'


