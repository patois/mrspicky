# MrsPicky

MrsPicky - An IDAPython decompiler script that helps auditing calls
to the memcpy() and memmove() functions.

This example code shows how the HexRays decompiler can be scripted in
order to identify potentially dangerous calls to memcpy() function calls.
It is in no way meant to be a fully working script covering all possible
use cases but just a few instead.

It will display a list of identified calls that can be and is meant to
be searched, sorted and filtered interactively using IDA's built-in
filtering features. Double clicking an entry will jump to the respective
call within the currently active IDA or Decompiler view.

In cases where the "n" argument that is passed to memcpy() calls can be
resolved statically, the resulting list's "max n" tab reflects the maximum
number of bytes that the destination buffer "dst" can be written to (in
other words: any number larger than that will corrupt whatever follows
the current stack frame, which usually is a return address.

The "problems" tab may contain the following keywords:

  * "memcorr" - indicates a confirmed memory corruption
  * "argptr"  - the "dst" pointer points beyond the local stack frame
                (this may not actually be a problem per se but...)

Feel free to adjust the script to suit your personal preferences.
Relevant code is commented and explained below so that hopefully it will
be easy to adapt the code to cover more use-cases as well as further
functions such as malloc() whatsoever.

For further help, check out vds5.py that comes with the HexRays SDK.

Have fun and don't forget to share your code :)

This script is licensed under the "THE BEER-WARE LICENSE" (Revision 42) license.

![mrspicky animated gif](/rsrc/picky.gif?raw=true)