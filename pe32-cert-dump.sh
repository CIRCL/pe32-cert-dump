#!/bin/bash
# Extract a security certificate from a signed Windows binary.
# Required software:
#   pedump (http://pedump.me/)
#   bc (http://www.gnu.org/software/bc/)
#   grep, tr, cut, dd, openssl

# This file is licensed under the GNU General Public License v3
# (C) 2012, CIRCL, Smile GIE
# (C) Sascha Rommelfangen, sascha.rommelfangen@circl.lu, @rommelfs

INFILE="$1"
if [ ! -e $INFILE ]
then
	echo "Extract certificate information"
	echo "from a signed Windows binary file"
	echo
	echo "Usage: $0 filename"
	exit 1
fi

if [[ `file $INFILE | grep PE32` ]]
then
  # Certificate location is referenced in PE header -> data-directory -> Security
  OFFSET=`pedump --data-directory $INFILE | grep SECURITY | tr -s " " | cut -d" " -f 4`
  LENGTH=`pedump --data-directory $INFILE | grep SECURITY | tr -s " " | cut -d" " -f 6`
  # BC does not handle lower case hex values correctly
  OFFSET=`echo $OFFSET | tr '[:lower:]' '[:upper:]'`
  LENGTH=`echo $LENGTH | tr '[:lower:]' '[:upper:]'`
  # Offset needs 8 bytes added 
  # (4 bytes dwLength + 2 bytes wRevision + 2 bytes wCertificateType)
  REALOFFSET=`echo "obase=16;ibase=16;$OFFSET+8" | bc`
  # Length is 8 bytes less and 1 byte less
  REALLENGTH=`echo "obase=16;ibase=16;$LENGTH-9" | bc`
  dd if=$INFILE bs=1 skip=0x$REALOFFSET count=0x$REALLENGTH | openssl asn1parse -inform DER 
fi
