# FindItByCalls
Hacky code for extracting calls in DLLs by function

Doesnt require loading library

Find an usage example in GetCalls.py

Notes:
* The dll path can be either absolute or relative
* The returned dictionary is indexed by function names in the format:
  * local!\<function name\> if the function was found in the export table
  * local!Function_0x\<function address in hex\> if the name couldnt be resolved
  * Function names from delay loaded libraries are no resolved (yet)
  * Switch statements blow my "decompiler", still thinking on a work around :)
