#!/bin/env python3

import sys
import os
import os.path
import re
import io

ALL_REGISTERS = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"]

RE_PLONK_BEGIN = re.compile("^!\s+PLONK\(([0-9]+)\):")
RE_PLONK_INSERT = re.compile("^!\s+INSERT\s+(.+)$")
RE_PLONK_CONSTANT = re.compile("\s+([a-zA-Z]+)\s+=\s+([^,\s]+)(,|$)")
RE_PLONK_END = re.compile("^!!$")

RE_STRING_ADDRESS = re.compile("""^("([^"]+)"|'([^']+)')""")
RE_VARIABLE_REGISTER = re.compile("\$([0-9]+)")
RE_ARGUMENTS_REGISTER = re.compile("\$A([0-9]+)")

RE_DEC_NUMBER_LITERAL = re.compile("([0-9_]+)")
RE_HEX_NUMBER_LITERAL = re.compile("(0x[a-fA-F0-9_]+)")
RE_BINARY_NUMBER_LITERAL = re.compile("(0b[0-1_]+)")

def match_number(value: str):
	match = RE_BINARY_NUMBER_LITERAL.match(value) or RE_HEX_NUMBER_LITERAL.match(value) or RE_DEC_NUMBER_LITERAL.match(value)
	if match is not None:
		number = match.group(1)
		base = 10
		if number.startswith("0x"):
			base = 16
		elif number.startswith("0b"):
			base = 2
		
		return True, int(number, base)
	
	return False, None

def match_string(value: str):
	match = RE_STRING_ADDRESS.match(value)
	if match is not None:
		return True, match.group(2)
	
	return False, None

class PlonkVariable:
	name: str
	register: str
	value = None

	def __init__(self, name, register, value = None):
		self.name = name
		self.register = register
		self.value = value
	
	def __str__(self):
		return f"{self.name}@{self.register}"

class PlonkContext:
	argument_registers = None
	constant_registers = None
	variable_registers = None

	def __init__(
		self,
		arguments = 0,
		constants = {},
		available_registers = ALL_REGISTERS
	):
		self.argument_registers = []
		self.constant_registers = {}
		self.variable_registers = {}

		registers = available_registers.copy()

		for x in range(arguments):
			self.argument_registers.append(
				registers.pop(0)
			)
		
		for key in constants:
			self.constant_registers[key] = PlonkVariable(
				key,
				registers.pop(),
				constants[key]
			)
		
		for register in reversed(registers):
			self.variable_registers[register] = { "free": True } 
	
	def __str__(self):
		return f"PlonkContext(args = {self.argument_registers}, constants = {self.constant_registers}, variables = {self.variable_registers})"
	
	def generate_initialization_code(self):
		code = ""
		for key in self.constant_registers:
			variable = self.constant_registers[key]

			if type(variable.value) is str:
				code += f"\tLDR {variable.register}, ={variable.value}\n"
			elif type(variable.value) is int:
				code += f"\tMOV {variable.register}, #0x{variable.value:X}\n"
			else:
				raise RuntimeError("Invalid constant value type")
		
		return code
	
	def get_constant(self, name: str) -> PlonkVariable:
		if not name in self.constant_registers:
			return None
		return self.constant_registers[name]

	def allocate_variable(self):
		for register in self.variable_registers:
			if self.variable_registers[register]["free"]:
				self.variable_registers[register]["free"] = False
				return register
		
		return None

	def check_variable(self, variable):
		if not variable in self.variable_registers:
			return False
		
		return self.variable_registers[variable]["free"]

	def free_variable(self, variable):
		if not variable in self.variable_registers:
			raise RuntimeError(f"Attempted to free non-existent register {variable}")
		
		if self.variable_registers[variable]["free"]:
			raise RuntimeError(f"Attempted to free already free register {variable}")
		
		self.variable_registers[variable]["free"] = True

class PlonkFileContext:
	plonking: bool = False
	context: PlonkContext = None

	variable_stack = []
	address_stack = []
	number_stack = []

	def __init__(self):
		pass

	def process_line(self, line: str):
		begin_match = RE_PLONK_BEGIN.match(line)
		if begin_match is not None:
			if self.plonking:
				raise RuntimeError("Can only plonk in one dimension at once")

			argc = int(begin_match.group(1))
			constants = {}
			for const_match in RE_PLONK_CONSTANT.finditer(
				line,
				begin_match.span()[1]
			):
				key = const_match.group(1)
				value = const_match.group(2)
				
				try:
					value = int(value)
				except:
					match = RE_STRING_ADDRESS.match(value)
					value = match.group(2)

				constants[key] = value
			
			self.plonking = True
			self.context = PlonkContext(
				arguments = argc,
				constants = constants
			)
			
			return self.context.generate_initialization_code()

		insert_match = RE_PLONK_INSERT.match(line)
		if insert_match is not None:
			path = insert_match.group(1)
			print(f"Inserting \"{path}\"", file = sys.stderr)

			outstream = io.StringIO("")
			with open(path, "r") as file:
				process_file(file, outstream)
			
			return outstream.getvalue()
		
		if not self.plonking:
			return line

		end_match = RE_PLONK_END.match(line)
		if end_match is not None:
			if not self.plonking:
				raise RuntimeError("Cannot plonk in negative")

			self.plonking = False
			self.context = None

			return None

		return self.process_line_plonking(line)
	
	def process_line_plonking(self, line: str):
		stripped = line.strip()
		if stripped == '':
			return line

		first_split = stripped.split(" ", maxsplit = 1)
		word = first_split[0]
		rest = None
		if len(first_split) > 1:
			rest = first_split[1]

		if word == "read":
			return self.process_read(rest)
		elif word == "write":
			return self.process_write()
		elif word == "alloc":
			return self.process_alloc(rest)
		elif word == "free":
			return self.process_free(rest)
		elif word == "store":
			return self.process_store(rest)
		elif word == "call":
			return self.process_call(rest)

		return self.process_other(line)

	def end(self):
		return None

	## GENERIC ABSTRACTION ##

	def resolve_argument(self, argument: str, target_stack):
		# try constants first
		constant = self.context.get_constant(argument)
		if constant is not None:
			target_stack.append(constant)
			register = constant.register
			
			return register, None

		# then try variables
		variable_match = RE_VARIABLE_REGISTER.match(argument)
		if variable_match is not None:
			index = int(variable_match.group(1))

			register = self.variable_stack[index]
			target_stack.append(
				PlonkVariable(f"${index}", register)
			)

			return register, None
		
		# then try arguments
		arguments_match = RE_ARGUMENTS_REGISTER.match(argument)
		if arguments_match is not None:
			index = int(arguments_match.group(1))

			register = self.context.argument_registers[index]
			target_stack.append(
				PlonkVariable(f"${index}", register)
			)

			return register, None
		
		# return None in case nothing matches
		return None, None

	def pop_argument(self, target_stack):
		value = target_stack.pop()
		if isinstance(value, PlonkVariable):
			return value.register
		
		self.context.free_variable(value)
		return value

	## RESOLVING VALUES ##

	def resolve_address(self, address_argument: str):
		address_register, code = self.resolve_argument(
			address_argument,
			self.address_stack
		)

		if address_register is not None:
			return address_register, code
		
		is_string, address = match_string(address_argument)
		if is_string:
			# allocate address register if the address is not a constant
			address_register = self.context.allocate_variable()
			self.address_stack.append(address_register)

			code = f"\tLDR {address_register}, ={address}\n"
		else:
			raise RuntimeError("Could not resolve argument {address_argument}")

		return address_register, code

	def pop_address(self):
		return self.pop_argument(self.address_stack)

	def resolve_number(self, number_argument: str):
		number_register, code = self.resolve_argument(number_argument, self.number_stack)

		if number_register is not None:
			return number_register, code

		is_number, number = match_number(number_argument)
		if is_number:
			# allocate number register if the number is not a constant
			number_register = self.context.allocate_variable()
			self.number_stack.append(number_register)

			code = f"\tMOV {number_register}, #0x{number:X}\n"
		else:
			raise RuntimeError("Could not resolve argument {number_argument}")
		
		return number_register, code

	def pop_number(self):
		return self.pop_argument(self.number_stack)

	## PROCESSING VALUES ##

	def process_read(self, rest: str):
		address_argument = rest.rstrip()
		
		code = ""

		address_register, address_code = self.resolve_address(address_argument)
		if address_code is not None:
			code = address_code

		var = self.context.allocate_variable()
		self.variable_stack.append(var)
		code += f"\tLDR {var}, [{address_register}]\n"
		
		return code

	def process_write(self):
		reg = self.variable_stack.pop()
		self.context.free_variable(reg)
		
		addr = self.pop_address()
		
		return f"\tSTR {reg}, [{addr}]\n"

	def process_alloc(self, rest: str):
		count = int(rest)

		for x in range(count):
			self.variable_stack.append(
				self.context.allocate_variable()
			)
	
	def process_free(self, rest: str):
		count = int(rest)

		for x in range(count):
			self.context.free_variable(
				self.variable_stack.pop()
			)
	
	def process_store(self, rest: str):
		split = rest.split(" ")
		target_argument = split[0]
		source_argument = split[1]

		code = ""

		target_register, target_code = self.resolve_address(target_argument)
		if target_code is not None:
			code = target_code

		source_register, source_code = self.resolve_number(source_argument)
		if source_code is not None:
			code += source_code

		code += f"\tSTR {source_register}, [{target_register}]\n"

		self.pop_number()
		self.pop_address()

		return code

	def process_call(self, rest: str):
		split = rest.split(" ")
		name = split[0]
		args = split[1:]

		overlapping_registers = []
		if len(args) > 0:
			overlapping_registers = ALL_REGISTERS[
				:min(len(args), len(self.context.argument_registers))
			]
			
			remaining_registers = ALL_REGISTERS[len(overlapping_registers) : len(args)]
			for reg in remaining_registers:
				if not self.context.check_variable(reg):
					overlapping_registers.append(reg)

		code = ""


		if len(overlapping_registers) > 0:
			regs = ", ".join(overlapping_registers)
			code += f"\tPUSH {{ {regs} }}\n"

		for x in range(len(args)):
			is_number, number = match_number(args[x])
			if is_number:
				code += f"\tMOV R{x}, #0x{number:X}\n"
				continue

			is_string, string = match_string(args[x])
			if is_string:
				code += f"\tLDR R{x}, ={string}\n"
				continue
			
		
		code += f"\tBL {name}\n"

		if len(overlapping_registers) > 0:
			regs = ", ".join(reversed(overlapping_registers))
			code += f"\tPOP {{ {regs} }}\n"

		return code

	def process_other(self, line: str):
		def transform_with(line: str, regex, callback):
			transformed_line = ""
			last_pos = 0

			for match in regex.finditer(line):
				span = match.span()

				transformed_line += line[last_pos:span[0]]
				transformed_line += callback(match)

				last_pos = span[1]

			transformed_line += line[last_pos:]

			return transformed_line

		line = transform_with(
			line,
			RE_BINARY_NUMBER_LITERAL,
			lambda match: f"0x{int(match.group(1), 2):X}"
		)

		line = transform_with(
			line,
			RE_VARIABLE_REGISTER,
			lambda match: self.variable_stack[int(match.group(1))]
		)

		line = transform_with(
			line,
			RE_ARGUMENTS_REGISTER,
			lambda match: self.context.argument_registers[int(match.group(1))]
		)

		return line

def process_file(stream, outstream):
	context = PlonkFileContext()
	
	for line in stream:
		output = context.process_line(line)
		if output is not None:
			print(output, file = outstream, end = "")
	
	final_output = context.end()
	if final_output is not None:
		print(final_output, file = outstream, end = "")
	

def process_folder(folder):
	files = os.listdir(folder)

	for file in files:
		if os.path.isfile(file):
			base, ext = os.path.splitext(file)
			if ext in [".plonk"]:
				out_path = os.path.join(
					os.path.dirname(folder),
					base + ".s"
				)

				print(f"## Processing {file} > {out_path}")

				with open(file, "r") as in_file:
					with open(out_path, "w") as out_file:
						process_file(in_file, out_file)

def main():
	if len(sys.argv) > 1:
		path = sys.argv[1]
		if os.path.isdir(path):
			process_folder(path)
		else:
			with open(path, "r") as file:
				process_file(file, sys.stdout)
	else:
		process_file(sys.stdin, sys.stdout)

main()