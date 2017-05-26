#!/bin/bash
# SAMBA is_known_pipename() vulnerability checker and patcher
# more info: CVE 2017-7494

function check_root_privileges {
if [[ $EUID != 0 ]] ; then
  echo "WARNING: We are not root so we will not be able to correct vulnerability if found"
  echo "Proceeding to assessment anyway"
fi
}

function getsambaversion {
sambaroute=$(which samba)
if [[ $? == 1 ]]; then echo "SAMBA seems not installed in this system. Nothing to do here o_O!"; exit; fi
echo "SAMBA found in ${sambaroute}. Checking its version..."
sambaversionstring=$(samba -V | cut -d" " -f 2 | cut -d"-" -f1) # cut here and there to isolate the numbers...
echo "Version seems to be ${sambaversionstring}"
# now we assign major, minor and revision numbers to separate vars
# (yeah, I know, there are more efficient ways of doing this than using echo and cut, but this is the most backwards compatible!!)
export sambamajor="$(echo $sambaversionstring | cut -d"." -f 1)"
export sambaminor="$(echo $sambaversionstring | cut -d"." -f 2)"
export sambarev="$(echo $sambaversionstring | cut -d"." -f3)"
}

function performcheck {
# Samba versions from 3.5.0 onwards are vulnerable
# Samba 4.6.4, 4.5.10 and 4.4.14 have been issued as security releases to correct the defect
# major version 3 && minor version > 4  == vulnerable
# major version 4 && minor version < 4  == vulnerable
# major version 4 && minor version = 4  && rev < 14 == vulnerable
# major version 4 && minor version = 5  && rev < 10 == vulnerable
# major version 4 && minor version = 6  && rev < 4  == vulnerable
# rest == safe

if [[ ( $sambamajor -eq 3 && $sambaminor -gt 4 ) || \
      ( $sambamajor -eq 4 && $sambaminor -lt 4 ) || \
      ( $sambamajor -eq 4 && $sambaminor -eq 4 && $sambarev -lt 14 ) || \
      ( $sambamajor -eq 4 && $sambaminor -eq 5 && $sambarev -lt 10 ) || \
      ( $sambamajor -eq 4 && $sambaminor -eq 6 && $sambarev -lt 4  ) ]]; then
  # vulnerable version 
  echo "The SAMBA version in this computer seems to be amongst the affected." 
  echo "Please do one of the following:"
  echo " a) upgrade SAMBA version"
  echo " b) patch a tarball of SAMBA sources, rebuild and reinstall"
  echo " c) disable named pipes in smb.conf"
  echo " d) better remove SAMBA from the system if you dont need it ;)"
else
  echo "System seems to have a version of SAMBA with no CVE 2017-4787 vulnerability. Yay! :)"

fi
}


## MAIN () ##
# check_root_privileges # not necessary yet, patching not implemented
getsambaversion
performcheck
exit
