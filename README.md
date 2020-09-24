# PLONK

**plonk** interj.
	
	The sound your head makes when hitting the table.

## ARM assembly preprocessor

Writing ARM assembly can be hard and tiresome. Who has the time to keep track of all registers and what values they hold.

Plonk is an ARM assembly preprocessor that uses special PLONK contexts to keep track of named, argument and variable registers. Each context tracks its own variable register allocations and helps with reading and writing memory as well.

## Example

Look at `test.plonk` and its expected output `test.expected.s`.