#!/bin/env python3

import sys
import os
import os.path
import re
import io

from typing import Tuple

LOW_REGISTERS = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"]
HIGH_REGISTERS = ["R8", "R9", "R10", "R11", "R12"]
# TODO: Only allow high registers if we run out of low registers
ALL_REGISTERS = LOW_REGISTERS
RESERVED_REGISTERS = ALL_REGISTERS[0:1]

RE_PLONK_BEGIN = re.compile("^!\s+PLONK\(([0-9]+)\):")
RE_PLONK_NAMED = re.compile("\s+([a-zA-Z_][a-zA-Z_0-9]*)\s+=\s+([^,\s]+)(,|$)")
RE_PLONK_END = re.compile("^!!$")
RE_PLONK_INSERT = re.compile("^!\s+INSERT\s+(.+)$")

RE_ASM_COMMENT = re.compile(";.*$")

RE_ADDRESS_TARGET = re.compile("\[([^]]+)\]")
def match_address_target(value: str) -> Tuple[bool, str]:
	"""Matches [[^]]+]"""
	match = RE_ADDRESS_TARGET.match(value)

	if match is not None:
		return True, match.group(1)
	
	return False, None

RE_ADDRESS_CONSTANT = re.compile("=([a-zA-Z_0-9]+)")
def match_address_constant(value: str) -> Tuple[bool, str]:
	"""Matches =ADDR"""
	match = RE_ADDRESS_CONSTANT.match(value)

	if match is not None:
		return True, match.group(1)
	
	return False, None

RE_NAMED_REGISTER = re.compile("\$([a-zA-Z_][a-zA-Z_0-9]+)")
def match_named_register(value: str) -> Tuple[bool, str]:
	"""Matches $[a-zA-Z_][a-zA-Z_0-9]+"""
	match = RE_NAMED_REGISTER.match(value)

	if match is not None:
		return True, match.group(1)
	
	return False, None

RE_ARGUMENT_REGISTER = re.compile("\$A([0-9]+)")
def match_argument_register(value: str) -> Tuple[bool, int]:
	"""Matches $A[0-9]+"""
	match = RE_ARGUMENT_REGISTER.match(value)

	if match is not None:
		return True, int(match.group(1))
	
	return False, None

RE_VARIABLE_REGISTER = re.compile("\$([0-9]+)")
def match_variable_register(value: str) -> Tuple[bool, int]:
	"""Matches $[0-9]+"""
	match = RE_VARIABLE_REGISTER.match(value)

	if match is not None:
		return True, int(match.group(1))
	
	return False, None

RE_RAW_REGISTER = re.compile("R([0-9]|1[0-2])")
def match_raw_register(value: str) -> Tuple[bool, str]:
	"""Matches R[0-9]|1[0-2]"""
	match = RE_RAW_REGISTER.match(value)

	if match is not None:
		return True, match.group(0)
	
	return False, None

RE_DEC_NUMBER_LITERAL = re.compile("([0-9_]+)")
RE_HEX_NUMBER_LITERAL = re.compile("(0x[a-fA-F0-9_]+)")
RE_BINARY_NUMBER_LITERAL = re.compile("(0b[0-1_]+)")
def match_number(value: str) -> Tuple[bool, int]:
	match = RE_BINARY_NUMBER_LITERAL.match(value)
	if match is not None:
		number = int(match.group(1), 2)

		return True, number

	match = RE_HEX_NUMBER_LITERAL.match(value)
	if match is not None:
		number = int(match.group(1), 16)

		return True, number

	match = RE_DEC_NUMBER_LITERAL.match(value)
	if match is not None:
		number = int(match.group(1), 10)

		return True, number

	return False, None

RE_STRING_ADDRESS = re.compile("""^("([^"]+)"|'([^']+)')""")
def match_string(value: str) -> Tuple[bool, str]:
	match = RE_STRING_ADDRESS.match(value)
	if match is not None:
		return True, match.group(2)
	
	return False, None

def code_line(value: str) -> str:
	return f"\t{value}\n"

class PlonkVariable:
	"""Represents a variable with optional initialization code and an assigned register."""
	name: str
	register: str
	code: str

	needs_free: bool

	def __init__(self, name, register, code = None, needs_free = False):
		self.name = name
		self.register = register
		self.code = code

		self.needs_free = needs_free
	
	def __str__(self):
		return f"{self.name}@{self.register}"

	def __repr__(self):
		return f"{self.__str__()} at 0x{id(self):X}"

class PlonkRegisterContext:
	"""Represents registers available throughout one PLONK context."""
	
	# Registers with assigned names
	named_registers: dict
	# Registers used for arguments
	argument_registers: list
	# Registers free to be allocated
	variable_registers: dict

	def __init__(
		self,
		arguments = 0,
		named_registers = {},
		available_registers = ALL_REGISTERS
	):
		self.named_registers = {}
		self.argument_registers = []
		self.variable_registers = {}

		registers = available_registers.copy()

		for x in range(arguments):
			self.argument_registers.append(
				PlonkVariable(
					f"$A{x}",
					registers.pop(0)
				)
			)
		
		for key in named_registers:
			reg = registers.pop()
			val = named_registers[key]

			code = ""
			if type(val) is str:
				code += code_line(f"LDR {reg}, ={val}")
			elif type(val) is int:
				code += code_line(f"MOV {reg}, #0x{val:X}")
			else:
				raise RuntimeError(f"Invalid constant value type {val}")

			self.named_registers[key] = PlonkVariable(
				key,
				reg,
				code
			)
		
		for register in registers:
			if register not in RESERVED_REGISTERS:
				self.variable_registers[register] = { "free": True }
	
	def __str__(self):
		return f"PlonkRegisterContext(named = {self.named_registers}, args = {self.argument_registers}, variables = {self.variable_registers})"
	
	def generate_initialization_code(self):
		code = ""
		for key in self.named_registers:
			code += self.named_registers[key].code
		
		return code
	
	def get_named(self, name: str) -> PlonkVariable:
		if not name in self.named_registers:
			return None
		
		return self.named_registers[name]

	def get_argument(self, index: int) -> PlonkVariable:
		if len(self.argument_registers) <= index:
			return None

		return self.argument_registers[index]

	def allocate_variable(self) -> PlonkVariable:
		for register in self.variable_registers:
			if self.variable_registers[register]["free"]:
				self.variable_registers[register]["free"] = False
				
				return PlonkVariable(None, register, None, needs_free = True)
		
		raise RuntimeError(f"Could not allocate register: {self}")

	def check_register(self, register: str):
		if register in RESERVED_REGISTERS:
			return True

		if not register in self.variable_registers:
			return False
		
		return self.variable_registers[register]["free"]

	def free_variable(self, variable: PlonkVariable):
		if not variable.register in self.variable_registers:
			raise RuntimeError(f"Attempted to free non-existent register {variable}")
		
		if self.variable_registers[variable.register]["free"]:
			raise RuntimeError(f"Attempted to free already free register {variable}")
		
		self.variable_registers[variable.register]["free"] = True

class PlonkRegisterStack:
	"""Represents a stack of PlonkVariables that can be pushed and poped with freeing when necessarry."""
	stack: list

	def __init__(self):
		self.stack = []

	def __str__(self):
		return f"{self.stack}"

	def push(self, variable: PlonkVariable):
		self.stack.append(variable)

	def get(self, index: int) -> PlonkVariable:
		if index < len(self.stack):
			return self.stack[index]
		return None

	def get_named(self, name: str) -> PlonkVariable:
		for var in self.stack:
			if var.name == name:
				return var
		
		return None

	def pop(self, context: PlonkRegisterContext) -> PlonkVariable:
		variable = self.stack.pop()

		if variable.needs_free:
			context.free_variable(variable)

		return variable

class PlonkFileState:
	"""Represents the Plonk state throughout a source file."""
	
	plonking: bool = False
	context: PlonkRegisterContext = None

	# variables addressable with $[0-9]+ syntax
	scoped_variables: PlonkRegisterStack
	# variables allocated but not addresable
	scoped_internal: PlonkRegisterStack

	def __init__(self):
		self.scoped_variables = PlonkRegisterStack()
		self.scoped_internal = PlonkRegisterStack()

	def process_line(self, line: str):
		# check for plonk beginning
		begin_match = RE_PLONK_BEGIN.match(line)
		if begin_match is not None:
			if self.plonking:
				raise RuntimeError("Can only plonk in one dimension at once")

			argc = int(begin_match.group(1))
			named_registers = {}
			for named_match in RE_PLONK_NAMED.finditer(
				line,
				begin_match.span()[1]
			):
				key = named_match.group(1)
				value = named_match.group(2)
				
				matches, matched_value = match_address_constant(value)
				if not matches:
					try:
						value = int(value)
					except:
						raise RuntimeError(f"Could not parse {value} as number nor address constant")
				else:
					value = matched_value

				named_registers[key] = value
			
			self.plonking = True
			self.context = PlonkRegisterContext(
				arguments = argc,
				named_registers = named_registers
			)
			
			return self.context.generate_initialization_code()

		# check for plonk insert
		insert_match = RE_PLONK_INSERT.match(line)
		if insert_match is not None:
			path = insert_match.group(1)
			print(f"Inserting \"{path}\"", file = sys.stderr)

			outstream = io.StringIO("")
			with open(path, "r") as file:
				process_file(file, outstream)
			
			return outstream.getvalue()

		# check for plonk ending
		end_match = RE_PLONK_END.match(line)
		if end_match is not None:
			if not self.plonking:
				raise RuntimeError("Cannot plonk in negative")

			self.plonking = False
			self.context = None

			return None

		# process the line specially when plonking
		if self.plonking:
			return self.process_line_plonking(line)

		# if not plonking then just return the current line
		return line
	
	def process_line_plonking(self, line: str):
		# strip comments and whitespace
		stripped = RE_ASM_COMMENT.sub("", line).strip()
		# ignore empty lines
		if stripped == '':
			return line

		first_split = stripped.split(" ", maxsplit = 1)
		word = first_split[0].lower()
		rest = None
		if len(first_split) > 1:
			rest = first_split[1]

		# self-contained
		if word == "store":
			return self.process_store(rest)
		
		if word == "call":
			return self.process_call(rest)
		elif word == "calln":
			return self.process_call(rest, nested = True)

		if word == "ifeq":
			return self.process_if(rest)
		elif word == "ifneq":
			return self.process_if(rest, check_instruction = "BNE")
		elif word == "ifgt":
			return self.process_if(rest, check_instruction = "BGT")

		# scoping
		if word == "read":
			return self.process_read(rest)
		elif word == "write":
			return self.process_write()
		elif word == "discard":
			return self.process_discard()
		
		if word == "alloc":
			return self.process_alloc(rest)
		elif word == "free":
			return self.process_free(rest)

		# other

		return self.process_other(line)

	def end(self):
		return None

	## MATCHERS ##

	def match_and_scope(self, value: str, *matchers) -> PlonkVariable:
		"""Returns the first match and scopes it into `self.scoped_internal`."""
		for matcher in matchers:
			match = matcher(value)
			if match is not None:
				self.scoped_internal.push(match)
				return match
		
		return None

	def match_and_code(self, value: str, target: str, *matchers) -> str:
		"""Returns the first match and creates a code line moving the value of the match into the target register"""
		for matcher in matchers:
			match = matcher(value)
			if match is not None:
				if match.needs_free:
					self.context.free_variable(match)

				if match.code is not None:
					return match.code.replace(match.register, target, 1)
				else:
					return code_line(f"MOV {target}, {match.register}")
		
		return None

	def match_address_constant(self, value: str) -> PlonkVariable:
		matches, address = match_address_constant(value)
		if matches:
			var = self.context.allocate_variable()
			return PlonkVariable(
				f"={address}",
				var.register,
				code_line(f"LDR {var.register}, ={address}"),
				needs_free = True
			)
		
		return None

	def match_argument_register(self, value: str) -> PlonkVariable:
		matches, index = match_argument_register(value)
		if matches:
			arg = self.context.get_argument(index)
			if arg is None:
				raise RuntimeError(f"Argument $A{index} does not exist")
			return PlonkVariable(f"$A{index}", arg.register)
		
		return None
	
	def match_variable_register(self, value: str) -> PlonkVariable:
		matches, index = match_variable_register(value)
		if matches:
			var = self.scoped_variables.get(index)
			if var is None:
				raise RuntimeError(f"Variable ${index} does not exist: {self.scoped_variables}")
			return PlonkVariable(f"${index}", var.register)
		
		return None
	
	def match_named_register(self, value: str) -> PlonkVariable:
		matches, name = match_named_register(value)
		if matches:
			named = self.scoped_variables.get_named(name)
			if named is None:
				named = self.context.get_named(name)
				if named is None:
					raise RuntimeError(f"Named register ${name} does not exist")
			return PlonkVariable(name, named.register)
		
		return None

	def match_raw_register(self, value: str) -> PlonkVariable:
		matches, register = match_raw_register(value)
		if matches:
			return PlonkVariable(register, register)

		return None

	def match_number(self, value: str) -> PlonkVariable:
		matches, number = match_number(value)
		if matches:
			var = self.context.allocate_variable()
			return PlonkVariable(
				f"#0x{number:X}",
				var.register,
				code_line(f"MOV {var.register}, #0x{number:X}"),
				needs_free = True
			)
		
		return None

	## SELF-CONTAINED ##

	def process_store(self, rest: str):
		"""
		store [=ADDR|$N|$AN|$NAMED|RAW] NUM|$N|$AN|$NAMED|RAW

		store [=ADDR] _ ->
			LDR RI, =ADDR
			STR _ ,[RI]
		
		store [$N|$AN|$NAMED|RAW] _ ->
			STR _, [$N|$AN|$NAMED|RAW]
		
		store _ NUM ->
			MOV RI, #NUM
			STR RI, _
		
		store _ $N|$AN|$NAMED|RAW ->
			STR $N|$AN|$NAMED|RAW, _
		"""
		split = rest.split(" ")
		target_argument_matches, target_argument = match_address_target(split[0])
		if not target_argument_matches:
			raise RuntimeError(f"First argument of store must match pattern `[[^]]+]`: {split[0]}")
		source_argument = split[1]

		code = ""

		target = self.match_and_scope(
			target_argument,
			self.match_address_constant,
			self.match_argument_register,
			self.match_variable_register,
			self.match_named_register,
			self.match_raw_register
		)
		if target.code is not None:
			code += target.code

		source = self.match_and_scope(
			source_argument,
			self.match_number,
			self.match_argument_register,
			self.match_variable_register,
			self.match_named_register,
			self.match_raw_register
		)
		if source.code is not None:
			code += source.code

		code += code_line(f"STR {source.register}, [{target.register}]")

		# pop both source and target
		self.scoped_internal.pop(self.context)
		self.scoped_internal.pop(self.context)

		return code

	def process_call(self, rest: str, nested = False):
		"""
		call|calln LABEL =ADDR|NUMBER|$N|$AN|$NAMED|RAW ...

		call _ =ADDR ->
			LDR R0, =ADDR
			BL _
		
		call _ NUMBER ->
			MOV R0, #NUMBER
			BL _

		call _ $N|$AN|$NAMED ->
			MOV R0, $N|$AN|$NAMED|RAW
			BL _
		
		calln _ _ ->
			_
			PUSH { LR }
			BL _
			POP { LR }
		"""
		split = rest.split(" ")
		label = split[0]
		arguments = split[1:]

		overlapping_registers = []
		if len(arguments) > 0:
			# overlapping with the current context arguments
			overlapping_registers = ALL_REGISTERS[
				:min(len(arguments), len(self.context.argument_registers))
			]
			
			# overlapping with the allocated ones or the constant ones
			remaining_registers = ALL_REGISTERS[len(overlapping_registers) : len(arguments)]
			for reg in remaining_registers:
				if not self.context.check_register(reg):
					overlapping_registers.append(reg)

		code = ""

		if len(overlapping_registers) > 0:
			regs = ", ".join(overlapping_registers)
			code += code_line(f"PUSH {{ {regs} }}")

		for x in range(len(arguments)):
			code += self.match_and_code(
				arguments[x],
				f"R{x}",
				self.match_number,
				self.match_address_constant,
				self.match_argument_register,
				self.match_variable_register,
				self.match_named_register,
				self.match_raw_register
			)
		
		if nested:
			code += code_line("PUSH { LR }")
		code += code_line(f"BL {label}")
		if nested:
			code += code_line("POP { LR }")

		if len(overlapping_registers) > 0:
			regs = ", ".join(reversed(overlapping_registers))
			code += code_line(f"POP {{ {regs} }}")

		return code

	def process_if(self, rest: str, check_instruction = "BEQ"):
		"""
		ifeq|ifneq =ADDR|$N|$AN|$NAMED|RAW =ADDR|NUM|$N|$AN|$NAMED|RAW LABEL

		ifeq =ADDR _ _ ->
			LDR RI, =ADDR
			CMP RI, _
			BEQ _
		
		ifeq $N|$AN|$NAMED|RAW _ _ ->
			CMP $N|$AN|$NAMED|RAW _
			BEQ _
		
		ifeq _ =ADDR _ ->
			LDR RI, =ADDR
			CMP _, RI
			BEQ _
		
		ifeq _ NUM _ ->
			CMP _, #NUM
			BEQ _
		
		ifeq _ $N|$AN|$NAMED|RAW _ ->
			CMP _, $N|$AN|$NAMED|RAW
			BEQ _

		ifeq _, _, LABEL ->
			BEQ LABEL

		ifneq _, _, LABEL ->
			BNE LABEL

		ifgt _, _, LABEL ->
			BGT LABEL
		"""
		split = rest.split(" ")
		left_argument = split[0]
		right_argument = split[1]
		label = split[2]

		code = ""

		left = self.match_and_scope(
			left_argument,
			self.match_address_constant,
			self.match_argument_register,
			self.match_variable_register,
			self.match_named_register,
			self.match_raw_register
		)
		if left.code is not None:
			code += left.code

		right_variable = self.match_and_scope(
			right_argument,
			self.match_address_constant,
			self.match_argument_register,
			self.match_variable_register,
			self.match_named_register,
			self.match_raw_register
		)
		if right_variable is not None:
			if right_variable.code is not None:
				code += right_variable.code

			code += code_line(f"CMP {left.register}, {right_variable.register}")
			
			self.scoped_internal.pop(self.context)
		else:
			matches, number = match_number(right_argument)
			if not matches:
				raise RuntimeError(f"Argument {right_argument} does not match any known right side")
			
			code += code_line(f"CMP {left.register}, #0x{number:X}")

		code += code_line(f"{check_instruction} {label}")

		# pop left
		self.scoped_internal.pop(self.context)

		return code

	## SCOPED ##

	def process_alloc(self, rest: str):
		"""
		alloc NAME =ADDR|NUM|$N|$AN|$NAMED|RAW
		
		Allocates a variable addressable with `$[0-9]+` and with an optional name syntax.
		"""
		name = None
		value_argument = None
		if rest is not None:
			split = rest.split(" ")
			if RE_NAMED_REGISTER.match(f"${split[0]}") is not None:
				name = split[0]
			
			if len(split) > 1:
				value_argument = split[1]

		var = self.context.allocate_variable()
		var.name = name
		self.scoped_variables.push(var)

		code = None
		if value_argument is not None:
			code = self.match_and_code(
				value_argument,
				var.register,
				self.match_address_constant,
				self.match_number,
				self.match_argument_register,
				self.match_variable_register,
				self.match_named_register,
				self.match_raw_register
			)

		return code
	
	def process_free(self, rest: str):
		"""
		free N

		Frees the last `N` addressable variables.
		"""
		count = int(rest or 1)

		for x in range(count):
			self.scoped_variables.pop(self.context)

	def process_read(self, rest: str):
		"""
		Allocates a new addressable variable and loads the value of `[=ADDR|$N|$AN|$NAMED|RAW]` into it.

		read [=ADDR|$N|$AN|$NAMED|RAW] NAME

		read [=ADDR] ->
			LDR RI, =ADDR
			LDR RV, [RI]
		
		read [$N|$AN|$NAMED|RAW]
			LDR RV, [$N|$AN|$NAMED|RAW]
		"""
		split = rest.split(" ")
		argument_matches, argument = match_address_target(split[0])
		if not argument_matches:
			raise RuntimeError(f"Argument of read must match pattern `[[^]]+]`: {rest}")
		
		name = None
		if len(split) > 1 and RE_NAMED_REGISTER.match(f"${split[1]}") is not None:
			name = split[1]

		code = ""

		address = self.match_and_scope(
			argument,
			self.match_address_constant,
			self.match_argument_register,
			self.match_variable_register,
			self.match_named_register,
			self.match_raw_register
		)
		if address.code is not None:
			code += address.code

		variable = self.context.allocate_variable()
		variable.name = name
		self.scoped_variables.push(variable)

		code += code_line(f"LDR {variable.register}, [{address.register}]")
		
		return code

	def process_write(self):
		"""
		Frees the last allocated addressable variabled and writes its value into the address specified by previous `read`.
		
		write

		write -> ; with previous `read =ADDR`
			STR RV, [RI]
		
		write -> ; with previous `read $N|$AN|$NAMED|RAW`
			STR RV, [$N|$AN|$NAMED|RAW]
		"""
		reg = self.scoped_variables.pop(self.context)
		addr = self.scoped_internal.pop(self.context)
		
		return code_line(f"STR {reg.register}, [{addr.register}]")

	def process_discard(self):
		"""
		Frees the last allocated addressable variable and discards its value. This can be used to end a `read` block without emitting a store.

		discard
		"""
		reg = self.scoped_variables.pop(self.context)
		addr = self.scoped_internal.pop(self.context)

		return None

	## OTHER ##

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

		# $0 -> RN
		line = transform_with(
			line,
			RE_VARIABLE_REGISTER,
			lambda match: self.scoped_variables.get(int(match.group(1))).register
		)

		# $A0 -> RN
		line = transform_with(
			line,
			RE_ARGUMENT_REGISTER,
			lambda match: self.context.argument_registers[int(match.group(1))].register
		)

		# $NAMED -> RN
		line = transform_with(
			line,
			RE_NAMED_REGISTER,
			lambda match: (
				self.scoped_variables.get_named(match.group(1))
				or
				self.context.get_named(match.group(1))
			).register
		)

		return line

def process_file(stream, outstream):
	context = PlonkFileState()
	line_number = 0
	
	for line in stream:
		line_number += 1
		try:
			output = context.process_line(line)
		except BaseException as e:
			raise RuntimeError(
				f""" Cannot process line #{line_number}
	{line.rstrip()}

	Reason: {e}
				"""
			)
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