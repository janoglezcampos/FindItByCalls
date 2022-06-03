# FindItByCalls
Hacky code for extracting calls in DLLs by function.
Use-Case: Find functions with known calls, also with little modifications.

! Im aware that the code is a chaos, adding features in prod never was a good idea :P

Find an usage example in GetCalls.py

Notes:
* Doesnt require loading library.
* The dll path can be either absolute or relative
* The returned dictionary is indexed by function names in the format:
  * local!\<function name\> if the function was found in the export table
  * local!Function_0x\<function address in hex\> if the name couldnt be resolved
  * Function names from delay loaded libraries are no resolved (yet)
  * Switch statements blow my "decompiler", still thinking on a work around :)
