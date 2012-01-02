#!/bin/bash
# Extract a security certificate from a signed Windows binary.
# Required software:
#   pedump (http://pedump.me/ - gem install pedump)
#   bc (http://www.gnu.org/software/bc/)
#   grep, tr, cut, dd, openssl

# Usage: Program expects a filename when run

# This file is licensed under the GNU General Public License v3
# (C) 2012, CIRCL, Smile GIE
# (C) Sascha Rommelfangen

INFILE="$1"
if [ ! -e $INFILE ]
then
	echo "Extract certificate information from a"
	echo " signed Windows binary file"
	echo
	echo "Usage: $0 filename"
	exit 1
fi

if [[ `file $INFILE | grep PE32` ]]
then
  # Certificate location is referenced in PE header -> data-directory -> Security
  OFFSET=`pedump --data-directory $INFILE |grep SECURITY|tr -s " " | cut -d" " -f 4`
  LENGTH=`pedump --data-directory $INFILE |grep SECURITY|tr -s " " | cut -d" " -f 6`
  # BC does not handle lower case hex values correctly
  OFFSET=`echo $OFFSET| tr '[:lower:]' '[:upper:]'`
  LENGTH=`echo $LENGTH| tr '[:lower:]' '[:upper:]'`
  # Offset needs 8 bytes added (4 bytes length + 4 bytes constant 0x00020200)
  REALOFFSET=`echo "obase=16;ibase=16;$OFFSET+8"|bc`
  # Length needs 8 bytes less and 1 byte less
  REALLENGTH=`echo "obase=16;ibase=16;$LENGTH-9"|bc`
  dd if=$INFILE bs=1 skip=0x$REALOFFSET count=0x$REALLENGTH | openssl asn1parse -inform DER 
fi
